"""Opt-in real UKey + running SDF daemon integration check.

Required environment variables:

- UKEY_TEST_PIN: sent only to the loopback UKey Agent and never printed or
  persisted by this script;
- UKEY_CERT_DIR: directory containing ukey-sign-certificate.cer and
  root-ca.cer. Keeping this explicit prevents local certificates and paths
  from becoming an accidental repository dependency.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import struct
import sys
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "web" / "backend"))

from app.ukey_auth import (  # noqa: E402
    base64url_decode,
    base64url_encode,
    sm2_public_point,
    validate_certificate_binding,
)


SM2_ID = b"1234567812345678"


class SDFWire:
    def send(self, command: int, body: bytes = b"") -> bytes:
        header = struct.pack("!8I", 0x53444658, 0x00020000, command, len(body), 0, 0, 0, 0)
        with socket.create_connection(("127.0.0.1", 18081), timeout=5) as connection:
            connection.sendall(header + body)
            returned = self._read(connection, 32)
            magic, version, returned_command, length, _, status, _, _ = struct.unpack("!8I", returned)
            payload = self._read(connection, length)
        if (magic, version, returned_command) != (0x53444658, 0x00020000, command):
            raise RuntimeError("invalid SDF response")
        if status != 0:
            raise RuntimeError(f"SDF status 0x{status:08x}")
        return payload

    @staticmethod
    def _read(connection: socket.socket, length: int) -> bytes:
        value = bytearray()
        while len(value) < length:
            chunk = connection.recv(length - len(value))
            if not chunk:
                raise RuntimeError("SDF connection closed early")
            value.extend(chunk)
        return bytes(value)

    def session(self) -> tuple[int, int]:
        device = struct.unpack("!Q", self.send(0x0001, struct.pack("!I16s", 0, b"")))[0]
        session = struct.unpack("!Q", self.send(0x0003, struct.pack("!Q", device)))[0]
        return device, session

    def close(self, device: int, session: int) -> None:
        self.send(0x0004, struct.pack("!Q", session))
        self.send(0x0002, struct.pack("!Q", device))

    @staticmethod
    def public_key(x: bytes, y: bytes) -> bytes:
        return struct.pack("=I", 256) + b"\0" * 32 + x + b"\0" * 32 + y

    def random(self, length: int) -> bytes:
        device, session = self.session()
        try:
            payload = self.send(0x0006, struct.pack("!QI", session, length))
            return payload[4:]
        finally:
            self.close(device, session)

    def digest(self, x: bytes, y: bytes, message: bytes) -> bytes:
        device, session = self.session()
        try:
            key = self.public_key(x, y)
            self.send(0x0010, struct.pack("!QI", session, 1) + key + struct.pack("!I", len(SM2_ID)) + SM2_ID)
            self.send(0x0011, struct.pack("!QI", session, len(message)) + message)
            payload = self.send(0x0012, struct.pack("!Q", session))
            length = struct.unpack("!I", payload[:4])[0]
            return payload[4:4 + length]
        finally:
            self.close(device, session)

    def verify(self, x: bytes, y: bytes, digest: bytes, signature: bytes) -> bool:
        device, session = self.session()
        try:
            payload = self.send(
                0x0036,
                struct.pack("!QI", session, 0x00020200) + self.public_key(x, y)
                + struct.pack("!II", len(digest), len(signature)) + digest + signature,
            )
            return struct.unpack("!I", payload)[0] == 0
        finally:
            self.close(device, session)

    def message_verify(self, x: bytes, y: bytes, message: bytes, signature: bytes) -> bool:
        return self.verify(x, y, self.digest(x, y, message), signature)


def agent_sign(message: bytes, pin: str) -> dict[str, object]:
    body = json.dumps({
        "challenge_base64url": base64url_encode(message),
        "pin": pin,
        "user_id": SM2_ID.decode("ascii"),
        "request_id": "cryptokit-real-ukey-integration",
    }).encode("utf-8")
    request = urllib.request.Request(
        "http://127.0.0.1:18088/v1/sign",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def run() -> None:
    pin = os.environ.get("UKEY_TEST_PIN")
    if not pin:
        raise RuntimeError("UKEY_TEST_PIN is required")
    certificate_directory = os.environ.get("UKEY_CERT_DIR")
    if not certificate_directory:
        raise RuntimeError("UKEY_CERT_DIR is required")
    certificate_root = Path(certificate_directory)
    user_der = (certificate_root / "ukey-sign-certificate.cer").read_bytes()
    ca_der = (certificate_root / "root-ca.cer").read_bytes()
    sdf = SDFWire()
    message = json.dumps(
        {
            "version": "1",
            "purpose": "cryptokit-real-ukey-integration",
            "nonce": base64url_encode(sdf.random(32)),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signed = agent_sign(message, pin)
    presented_der = base64.b64decode(str(signed["certificate_base64"]), validate=True)
    signature = base64url_decode(str(signed["signature_base64url"]))
    agent_digest = base64url_decode(str(signed["digest_base64url"]))
    validation = validate_certificate_binding(
        user_der, ca_der,
        lambda x, y, value, raw_signature: sdf.message_verify(x, y, value, raw_signature),
    )
    x, y = sm2_public_point(user_der)
    digest = sdf.digest(x, y, message)
    verified = sdf.verify(x, y, digest, signature)
    result = {
        "ok": bool(
            signed.get("ok")
            and presented_der == user_der
            and agent_digest == digest
            and verified
            and validation["chain_valid"]
        ),
        "certificate_match": presented_der == user_der,
        "digest_match": agent_digest == digest,
        "signature_verified_by_sdf": verified,
        "certificate_chain_verified_by_sdf": validation["chain_valid"],
        "device": signed.get("device"),
        "application": signed.get("application"),
        "container": signed.get("container"),
    }
    print(json.dumps(result, ensure_ascii=False))
    if not result["ok"]:
        raise RuntimeError("real UKey integration failed")


if __name__ == "__main__":
    run()
