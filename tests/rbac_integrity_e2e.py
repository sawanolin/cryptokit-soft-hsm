#!/usr/bin/env python3
from __future__ import annotations
import argparse, http.cookiejar, json, urllib.error, urllib.request

class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = None
    def call(self, path, method="GET", body=None, expected=200, raw=False):
        data = None if body is None else json.dumps(body).encode()
        headers = {"Content-Type": "application/json"}
        if self.csrf and method not in ("GET", "HEAD"):
            headers["X-CSRF-Token"] = self.csrf
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=20) as response:
                content = response.read()
                payload = content.decode() if raw else json.loads(content)
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
            content = error.read()
            payload = content.decode() if raw else json.loads(content)
        assert status == expected, (path, status, payload)
        return payload
    def login(self, username, password):
        result = self.call("/api/auth/login", "POST", {"username": username, "password": password})
        self.csrf = result["csrf"]
        return result
    def logout(self):
        self.call("/api/auth/logout", "POST", {})
        self.csrf = None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:28080")
    args = parser.parse_args()
    super_client = Client(args.base_url)
    assert super_client.call("/api/health")["initialized"] is False
    super_client.call("/api/initialize", "POST", {
        "username": "rootadmin", "password": "Root!Admin2026",
        "vendor": "CryptoKit", "device_name": "SoftHSM-RBAC", "serial": "RBAC000001"
    }, expected=201)
    login = super_client.login("rootadmin", "Root!Admin2026")
    assert login["role"] == "super_admin" and "administrators" in login["pages"]
    super_client.call("/api/keys", expected=403)
    super_client.call("/api/status", expected=403)
    super_client.call("/api/device", expected=403)
    for username, password, role in (
        ("sysadmin", "System!Admin2026", "system_admin"),
        ("secadmin", "Security!Admin2026", "security_admin"),
        ("auditor", "Audit!Admin2026", "audit_admin"),
    ):
        super_client.call("/api/administrators", "POST", {"username": username, "password": password, "role": role}, expected=201)
    assert len(super_client.call("/api/administrators")) == 4
    super_client.logout()

    security = Client(args.base_url)
    login = security.login("secadmin", "Security!Admin2026")
    assert login["pages"] == ["keys", "testing"]
    security.call("/api/keys", "POST", {"type": "sign", "index": 1, "password": ""}, expected=201)
    security.call("/api/keys", "POST", {"type": "enc", "index": 2, "password": ""}, expected=201)
    keys = security.call("/api/keys")
    assert {(k["type"], k["index"]) for k in keys} == {("sign", 1), ("enc", 2)}
    assert all(k["integrity"] and not k["password_protected"] for k in keys)
    assert security.call("/api/keys/sign/1/verify", "POST", {})["valid"] is True
    security.call("/api/keys/enc/2/reindex", "POST", {"new_index": 7})
    assert {(k["type"], k["index"]) for k in security.call("/api/keys")} == {("sign", 1), ("enc", 7)}
    assert security.call("/api/keys/enc/7/verify", "POST", {})["valid"] is True
    security.call("/api/keys", "POST", {"algorithm": "RSA", "bits": 2048, "type": "sign", "index": 3, "password": ""}, expected=201)
    security.call("/api/keys", "POST", {"algorithm": "RSA", "bits": 2048, "type": "enc", "index": 4, "password": ""}, expected=201)
    assert security.call("/api/keys/sign/3/verify?algorithm=RSA", "POST", {})["valid"] is True
    security.call("/api/keys/sign/3/reindex?algorithm=RSA", "POST", {"new_index": 8})
    keys = security.call("/api/keys")
    assert {(k["algorithm"], k["type"], k["index"]) for k in keys} == {
        ("SM2", "sign", 1), ("SM2", "enc", 7),
        ("RSA", "sign", 8), ("RSA", "enc", 4),
    }
    assert security.call("/api/keys/sign/8/verify?algorithm=RSA", "POST", {})["valid"] is True
    security.call("/api/keks", "POST", {"index": 1}, expected=201)
    keks = security.call("/api/keks")
    assert len(keks) == 1 and keks[0]["integrity"] is True
    assert security.call("/api/keks/1/verify", "POST", {})["valid"] is True
    selftest = security.call("/api/crypto/selftest", "POST", {})
    assert selftest["status"] == "passed" and selftest["rsa"]["status"] == "passed"
    security.call("/api/audit", expected=403)
    security.logout()

    system = Client(args.base_url)
    login = system.login("sysadmin", "System!Admin2026")
    assert "sessions" in login["pages"] and "keys" not in login["pages"]
    assert system.call("/api/status")["daemon"]["status"] == "running"
    backup = system.call("/api/backups", "POST", {}, expected=201)
    assert len(backup["id"]) == 32
    system.call("/api/keys", expected=403)
    system.logout()

    audit = Client(args.base_url)
    login = audit.login("auditor", "Audit!Admin2026")
    assert login["pages"] == ["audit"]
    settings = audit.call("/api/audit/settings")
    assert settings == {"retention_days": 365, "display_level": "INFO"}
    updated = audit.call("/api/audit/settings", "PATCH", {"retention_days": 730, "display_level": "DEBUG"})
    assert updated == {"retention_days": 730, "display_level": "DEBUG"}
    events = audit.call("/api/audit?limit=200")
    assert len(events) >= 10 and all("request_id" in event for event in events)
    text = audit.call("/api/audit/export", raw=True)
    assert "administrator_create" in text and "integrity_verify" in text and "request:" in text
    audit.call("/api/keys", expected=403)
    print(json.dumps({"result":"passed","roles":4,"keys":["sm2-sign:1","sm2-enc:7","rsa-sign:8","rsa-enc:4"],"integrity":"HMAC-SM3","audit_export":"txt"}, ensure_ascii=False))

if __name__ == "__main__":
    main()
