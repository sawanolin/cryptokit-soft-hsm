#!/usr/bin/env python3
"""Exercise the destructive Web reset confirmation contract."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import urllib.error
import urllib.request


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar)
    )

    def call(path, method="GET", body=None, csrf=None, expected=200):
        headers = {"Content-Type": "application/json"}
        if csrf:
            headers["X-CSRF-Token"] = csrf
        request = urllib.request.Request(
            base + path,
            data=None if body is None else json.dumps(body).encode(),
            headers=headers,
            method=method,
        )
        try:
            with opener.open(request, timeout=15) as response:
                status = response.status
                payload = json.loads(response.read())
        except urllib.error.HTTPError as error:
            status = error.code
            payload = json.loads(error.read())
        assert status == expected, (path, status, payload)
        return payload

    login = call(
        "/api/auth/login",
        "POST",
        {"username": "admin", "password": "Admin!Pass2026"},
    )
    csrf = login["csrf"]
    call(
        "/api/device/reset",
        "POST",
        {
            "password": "Admin!Pass2026",
            "serial": "WRONG",
            "confirmation": "RESET DEVICE",
        },
        csrf,
        expected=403,
    )
    result = call(
        "/api/device/reset",
        "POST",
        {
            "password": "Admin!Pass2026",
            "serial": "E2E000001",
            "confirmation": "RESET DEVICE",
        },
        csrf,
    )
    assert result["reset"] is True
    health = call("/api/health")
    assert health["initialized"] is False
    call(
        "/api/auth/login",
        "POST",
        {"username": "admin", "password": "Admin!Pass2026"},
        expected=409,
    )
    print(json.dumps({"result": "passed", "reset": "complete"}))


if __name__ == "__main__":
    main()
