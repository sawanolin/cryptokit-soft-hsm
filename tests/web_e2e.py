#!/usr/bin/env python3
"""End-to-end smoke test for the local Web management plane."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import urllib.error
import urllib.request

from web_password import password_hash, password_material


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def call(path: str, method: str = "GET", body=None, csrf=None, expected=200):
        data = None if body is None else json.dumps(body).encode()
        headers = {"Content-Type": "application/json"}
        if csrf:
            headers["X-CSRF-Token"] = csrf
        request = urllib.request.Request(
            base + path, data=data, headers=headers, method=method
        )
        try:
            with opener.open(request, timeout=10) as response:
                payload = json.loads(response.read())
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
            payload = json.loads(error.read())
        assert status == expected, (path, status, payload)
        return payload

    health = call("/api/health")
    assert health["status"] == "ok"
    assert health["initialized"] is False

    initial_password = password_material(
        "Admin!Pass2026",
        call(
            "/api/auth/initialize-password-salt", "POST", {"username": "admin"}
        ),
    )
    call(
        "/api/initialize",
        "POST",
        {
            "username": "admin",
            "password": initial_password,
            "vendor": "CryptoKit",
            "device_name": "SoftHSM-0018",
            "serial": "E2E000001",
            "create_sign_key": True,
            "create_enc_key": True,
            "create_kek": True,
            "kek_index": 1,
            "key_password": "Key!Pass2026",
        },
        expected=201,
    )
    account_salt = call("/api/auth/password-salt?username=admin")["salt_base64"]
    admin_password = password_hash("Admin!Pass2026", account_salt)
    call(
        "/api/auth/login",
        "POST",
        {"username": "admin", "password": password_hash("incorrect", account_salt)},
        expected=401,
    )
    login = call(
        "/api/auth/login",
        "POST",
        {"username": "admin", "password": admin_password},
    )
    csrf = login["csrf"]
    session = call("/api/auth/session")
    assert session["username"] == "admin"

    status = call("/api/status")
    assert status["daemon"]["status"] == "running"
    assert status["daemon"]["keys"] == 2
    keys = call("/api/keys")
    assert {(item["type"], item["index"]) for item in keys} == {
        ("sign", 1),
        ("enc", 1),
    }
    keks = call("/api/keks")
    assert len(keks) == 1 and keks[0]["index"] == 1 and keks[0]["enabled"] is True
    assert len(keks[0]["fingerprint"]) == 64
    assert keks[0]["integrity"] is True
    assert call("/api/keks/1/verify", "POST", {}, csrf)["valid"] is True
    call("/api/keks/1/disable", "POST", {}, csrf)
    assert call("/api/keks")[0]["enabled"] is False
    call("/api/keks/1/enable", "POST", {}, csrf)
    call("/api/keks", "POST", {"index": 2}, csrf, expected=201)
    call(
        "/api/keks/2", "DELETE",
        {"password": admin_password, "confirmation": "DELETE"}, csrf,
    )
    backup = call("/api/backups", "POST", {}, csrf, expected=201)
    backup_id = backup["id"]
    assert len(backup_id) == 32 and backup["size"] > 1024
    assert any(item["id"] == backup_id for item in call("/api/backups"))

    call("/api/keys/sign/1/disable", "POST", {}, csrf)
    assert next(item for item in call("/api/keys") if item["type"] == "sign")[
        "enabled"
    ] is False
    call("/api/keys/sign/1/enable", "POST", {}, csrf)

    public = call("/api/keys/sign/1/public")
    assert public["format"] == "GMT-0018-ECCrefPublicKey"
    assert len(public["data"]) > 100

    call(
        "/api/keys/sign/1/password", "POST",
        {"old_password": "Key!Pass2026", "new_password": "Key!Pass2026-Next"}, csrf,
    )
    call(
        "/api/keys/sign/1/password", "POST",
        {"old_password": "Key!Pass2026-Next", "new_password": "Key!Pass2026"}, csrf,
    )

    call(
        "/api/keys",
        "POST",
        {"type": "sign", "index": 2, "password": "Temp!Key2026"},
        csrf,
        expected=201,
    )
    call(
        "/api/keys/sign/2",
        "DELETE",
        {"password": admin_password, "confirmation": "DELETE"},
        csrf,
    )
    call(
        "/api/crypto/random?length=32",
        "POST",
        {},
        csrf,
    )
    selftest = call("/api/crypto/selftest", "POST", {}, csrf)
    assert selftest["status"] == "passed"
    assert all(selftest[name]["status"] == "passed" for name in ("random", "sm3", "sm4", "sm2"))
    assert len(call("/api/audit")) >= 7
    call("/api/keys/enc/1/disable", "POST", {}, expected=403)
    call(
        "/api/backups/restore", "POST",
        {"backup_id": backup_id, "password": admin_password, "confirmation": "RESTORE"},
        csrf,
    )
    call("/api/auth/session", expected=401)
    login = call(
        "/api/auth/login", "POST",
        {"username": "admin", "password": admin_password},
    )
    csrf = login["csrf"]
    call(
        f"/api/backups/{backup_id}", "DELETE",
        {"password": admin_password, "confirmation": "DELETE"}, csrf,
    )
    health = call("/api/health")
    assert health["initialized"] is True
    print(
        json.dumps(
            {
                "result": "passed",
                "daemon": status["daemon"]["status"],
                "keys": status["daemon"]["keys"],
                "csrf_rejection": "passed",
                "random_path": "passed",
                "crypto_selftest": "passed",
                "backup_restore": "passed",
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
