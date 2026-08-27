#!/usr/bin/env python3
"""Exercise Web session inventory and administrative termination."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import socket
import struct
import urllib.request

from web_password import password_hash


MAGIC = 0x53444658
VERSION = 0x00020000


def sdf_send(host: str, port: int, command: int, body: bytes) -> tuple[int, bytes]:
    request = struct.pack("!8I", MAGIC, VERSION, command, len(body), 0, 0, 0, 0)
    with socket.create_connection((host, port), timeout=5) as connection:
        connection.sendall(request + body)
        header = b""
        while len(header) < 32:
            header += connection.recv(32 - len(header))
        values = struct.unpack("!8I", header)
        payload = b""
        while len(payload) < values[3]:
            payload += connection.recv(values[3] - len(payload))
    return values[5], payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--daemon-host", default="127.0.0.1")
    parser.add_argument("--daemon-port", type=int, default=18081)
    args = parser.parse_args()
    base = args.base_url.rstrip("/")

    status, payload = sdf_send(
        args.daemon_host, args.daemon_port, 0x0001, struct.pack("!I16s", 0, b"")
    )
    assert status == 0 and len(payload) == 8
    device_id = struct.unpack("!Q", payload)[0]
    status, payload = sdf_send(
        args.daemon_host, args.daemon_port, 0x0003, struct.pack("!Q", device_id)
    )
    assert status == 0 and len(payload) == 8
    session_id = struct.unpack("!Q", payload)[0]

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def call(path: str, method="GET", body=None, csrf=None):
        headers = {"Content-Type": "application/json"}
        if csrf:
            headers["X-CSRF-Token"] = csrf
        request = urllib.request.Request(
            base + path,
            data=None if body is None else json.dumps(body).encode(),
            headers=headers,
            method=method,
        )
        with opener.open(request, timeout=10) as response:
            return json.loads(response.read())

    account_salt = call("/api/auth/password-salt?username=admin")["salt_base64"]
    admin_password = password_hash("Admin!Pass2026", account_salt)
    login = call(
        "/api/auth/login",
        "POST",
        {"username": "admin", "password": admin_password},
    )
    sessions = call("/api/sessions")
    assert any(item["session_id"] == session_id for item in sessions)
    call(
        f"/api/sessions/{session_id}",
        "DELETE",
        {"password": admin_password, "confirmation": "TERMINATE"},
        login["csrf"],
    )
    assert not any(
        item["session_id"] == session_id for item in call("/api/sessions")
    )
    status, _ = sdf_send(
        args.daemon_host, args.daemon_port, 0x0004, struct.pack("!Q", session_id)
    )
    assert status != 0
    sdf_send(
        args.daemon_host, args.daemon_port, 0x0002, struct.pack("!Q", device_id)
    )
    print(json.dumps({"result": "passed", "terminated_session": session_id}))


if __name__ == "__main__":
    main()
