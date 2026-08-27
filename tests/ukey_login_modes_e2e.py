"""Opt-in Web end-to-end check for both administrator login modes.

Requires a fresh 1.1.4 Web container, a running local UKey Agent, and the same
UKEY_TEST_PIN/UKEY_CERT_DIR environment variables as ukey_auth_integration.py.
No PIN or certificate content is printed or persisted by this script.
"""

from __future__ import annotations

import base64
import http.cookiejar
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from ukey_auth_integration import SM2_ID, agent_sign
from web_password import password_hash, password_material


BASE_URL = os.environ.get("UKEY_WEB_BASE_URL", "http://127.0.0.1:18080")
TEST_USERNAME = "ukey_mode_admin"
TEST_PASSWORD = "UKey-Mode-Test-Password-114!"


class WebClient:
    def __init__(self) -> None:
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies)
        )
        self.csrf = ""

    def request(self, path: str, method: str = "GET", body: dict | None = None) -> dict:
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.csrf and method not in {"GET", "HEAD"}:
            headers["X-CSRF-Token"] = self.csrf
        request = urllib.request.Request(
            BASE_URL + path, data=data, headers=headers, method=method
        )
        with self.opener.open(request, timeout=20) as response:
            result = json.load(response)
        if isinstance(result, dict) and result.get("csrf"):
            self.csrf = str(result["csrf"])
        return result

    def expect_denied(self, path: str, method: str, body: dict) -> None:
        try:
            self.request(path, method, body)
        except urllib.error.HTTPError as error:
            if error.code in {401, 403, 409}:
                return
            raise
        raise RuntimeError(f"request unexpectedly succeeded: {method} {path}")

    def expect_invalid(self, path: str, method: str, body: dict) -> None:
        try:
            self.request(path, method, body)
        except urllib.error.HTTPError as error:
            if error.code == 422:
                return
            raise
        raise RuntimeError(f"invalid request unexpectedly succeeded: {method} {path}")


def ukey_login(client: WebClient, pin: str, password: str) -> dict:
    salt = client.request(
        f"/api/auth/password-salt?username={urllib.parse.quote(TEST_USERNAME)}"
    )["salt_base64"]
    challenge = client.request(
        "/api/auth/ukey/challenge",
        "POST",
        {"username": TEST_USERNAME, "password": password_hash(password, salt)},
    )
    signed = agent_sign(
        base64.urlsafe_b64decode(
            str(challenge["challenge_base64url"])
            + "=" * (-len(str(challenge["challenge_base64url"])) % 4)
        ),
        pin,
    )
    return client.request(
        "/api/auth/ukey/verify",
        "POST",
        {
            "username": TEST_USERNAME,
            "challenge_id": challenge["challenge_id"],
            "signature_base64url": signed["signature_base64url"],
            "digest_base64url": signed["digest_base64url"],
            "certificate_base64": signed["certificate_base64"],
        },
    )


def run() -> None:
    pin = os.environ.get("UKEY_TEST_PIN")
    certificate_directory = os.environ.get("UKEY_CERT_DIR")
    if not pin or not certificate_directory:
        raise RuntimeError("UKEY_TEST_PIN and UKEY_CERT_DIR are required")
    cert_root = Path(certificate_directory)
    user_certificate = base64.b64encode(
        (cert_root / "ukey-sign-certificate.cer").read_bytes()
    ).decode("ascii")
    ca_certificate = base64.b64encode(
        (cert_root / "root-ca.cer").read_bytes()
    ).decode("ascii")

    admin = WebClient()
    initial_password = password_material(
        TEST_PASSWORD,
        admin.request(
            "/api/auth/initialize-password-salt",
            "POST",
            {"username": TEST_USERNAME},
        ),
    )
    admin.request(
        "/api/initialize",
        "POST",
        {"username": TEST_USERNAME, "password": initial_password},
    )
    account_salt = admin.request(
        f"/api/auth/password-salt?username={urllib.parse.quote(TEST_USERNAME)}"
    )["salt_base64"]
    correct_password = password_hash(TEST_PASSWORD, account_salt)
    password_session = admin.request(
        "/api/auth/login",
        "POST",
        {"username": TEST_USERNAME, "password": correct_password},
    )
    admin.request(
        f"/api/administrators/{TEST_USERNAME}/ukey",
        "PUT",
        {
            "enabled": True,
            "user_certificate_base64": user_certificate,
            "ca_certificate_base64": ca_certificate,
        },
    )

    admin.expect_denied(
        "/api/auth/ukey/challenge", "POST",
        {"username": TEST_USERNAME, "password": correct_password},
    )
    admin.expect_invalid(
        f"/api/administrators/{TEST_USERNAME}",
        "PATCH",
        {"login_mode": "ukey_only"},
    )
    admin.request(
        f"/api/administrators/{TEST_USERNAME}",
        "PATCH",
        {"login_mode": "password_ukey"},
    )
    admin.expect_denied(
        "/api/auth/ukey/challenge", "POST",
        {"username": TEST_USERNAME, "password": password_hash("Wrong-Password-114!", account_salt)},
    )
    WebClient().expect_denied(
        "/api/auth/login",
        "POST",
        {"username": TEST_USERNAME, "password": correct_password},
    )
    combined_session = ukey_login(admin, pin, TEST_PASSWORD)

    print(json.dumps({
        "ok": True,
        "version": admin.request("/api/health")["version"],
        "password_mode": password_session.get("role") == "super_admin",
        "removed_ukey_only_mode_rejected": True,
        "password_ukey_mode": (
            combined_session.get("authentication")
            == "password-and-ukey-sm2-challenge"
        ),
        "sdf_user_id": SM2_ID.decode("ascii"),
    }, ensure_ascii=False))


if __name__ == "__main__":
    run()
