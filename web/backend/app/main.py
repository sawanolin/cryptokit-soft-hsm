from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import http.client
import io
import json
import math
import os
import re
import secrets
import socket
import sqlite3
import struct
import threading
import time
import xmlrpc.client
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .ukey_auth import (
    UKeyCertificateError,
    base64url_decode,
    base64url_encode,
    decode_certificate,
    sm2_public_point,
    validate_certificate_binding,
)


PRODUCT_NAME = "CryptoKit 软件服务器密码机管理平台"
PRODUCT_VERSION = "1.1.4"
DATA_ROOT = Path(os.getenv("SDFX_DATA_DIR", "/var/lib/sdfx")).resolve()
WEB_ROOT = DATA_ROOT / "web"
STATE_FILE = WEB_ROOT / "state.json"
DATABASE_FILE = WEB_ROOT / "manager.db"
BACKUP_ROOT = DATA_ROOT / "backups"
TOKEN_FILE = Path(os.getenv("SDFX_ADMIN_TOKEN_FILE", "/run/sdfx/admin.token"))
SUPERVISOR_SOCKET = Path(os.getenv("SDFX_SUPERVISOR_SOCKET", "/run/sdfx/supervisor.sock"))
DAEMON_LISTEN_HOST = os.getenv("SDFX_DAEMON_LISTEN_HOST", "0.0.0.0")
STATIC_ROOT = Path(__file__).resolve().parent.parent / "static"
SESSION_TTL = int(os.getenv("SDFX_WEB_SESSION_TTL", "1800"))
COOKIE_SECURE = os.getenv("SDFX_WEB_SECURE_COOKIE", "false").lower() == "true"
COOKIE_NAME = "sdfx_manager_session"
UKEY_FLOW_COOKIE_NAME = "sdfx_ukey_flow"
UKEY_CHALLENGE_TTL = 60
UKEY_SM2_ID = b"1234567812345678"
PASSWORD_SALT_BYTES = 8
PASSWORD_HASH_BYTES = 32
PASSWORD_SALT_TICKET_TTL = 300

MAGIC = 0x53444658
VERSION = 0x00020000
SDR_OK = 0
SDR_KEYERR = 0x01000015
CMD_OPEN_DEVICE = 0x0001
CMD_CLOSE_DEVICE = 0x0002
CMD_OPEN_SESSION = 0x0003
CMD_CLOSE_SESSION = 0x0004
CMD_GENERATE_RANDOM = 0x0006
CMD_HASH_INIT = 0x0010
CMD_HASH_UPDATE = 0x0011
CMD_HASH_FINAL = 0x0012
CMD_EXTERNAL_VERIFY_ECC = 0x0036
CMD_ADMIN_STATUS = 0x0060
CMD_ADMIN_KEY_LIST = 0x0061
CMD_ADMIN_KEY_CREATE = 0x0062
CMD_ADMIN_KEY_DELETE = 0x0063
CMD_ADMIN_KEY_ENABLE = 0x0064
CMD_ADMIN_KEY_DISABLE = 0x0065
CMD_ADMIN_KEY_PUBLIC = 0x0066
CMD_ADMIN_KEY_PASSWORD = 0x0067
CMD_ADMIN_DEVICE_CONFIG = 0x0068
CMD_ADMIN_SESSION_LIST = 0x0069
CMD_ADMIN_SESSION_CLOSE = 0x006A
CMD_ADMIN_KEK_LIST = 0x006B
CMD_ADMIN_KEK_CREATE = 0x006C
CMD_ADMIN_KEK_DELETE = 0x006D
CMD_ADMIN_KEK_ENABLE = 0x006E
CMD_ADMIN_KEK_DISABLE = 0x006F
CMD_ADMIN_BACKUP_LIST = 0x0070
CMD_ADMIN_BACKUP_CREATE = 0x0071
CMD_ADMIN_BACKUP_RESTORE = 0x0072
CMD_ADMIN_BACKUP_DELETE = 0x0073
CMD_ADMIN_DEVICE_RESET = 0x0074
CMD_ADMIN_SELFTEST = 0x0075
CMD_ADMIN_INTEGRITY_INIT = 0x0076
CMD_ADMIN_KEY_VERIFY = 0x0077
CMD_ADMIN_KEY_REINDEX = 0x0078
CMD_ADMIN_RSA_KEY_LIST = 0x0079
CMD_ADMIN_RSA_KEY_CREATE = 0x007A
CMD_ADMIN_RSA_KEY_DELETE = 0x007B
CMD_ADMIN_RSA_KEY_ENABLE = 0x007C
CMD_ADMIN_RSA_KEY_DISABLE = 0x007D
CMD_ADMIN_RSA_KEY_PUBLIC = 0x007E
CMD_ADMIN_RSA_KEY_PASSWORD = 0x007F
CMD_ADMIN_RSA_KEY_VERIFY = 0x0080
CMD_ADMIN_RSA_KEY_REINDEX = 0x0081
CMD_ADMIN_KEK_VERIFY = 0x008C

KEY_TYPES = {"sign": 1, "enc": 2}
ROLES = {"super_admin", "system_admin", "security_admin", "audit_admin"}
LOGIN_MODES = {"password", "password_ukey"}
LOGIN_MODE_LABELS = {
    "password": "用户名+口令",
    "password_ukey": "用户名+口令+UKey",
}
ROLE_LABELS = {
    "super_admin": "超级管理员",
    "system_admin": "系统管理员",
    "security_admin": "安全管理员",
    "audit_admin": "审计管理员",
}
ROLE_PAGES = {
    "super_admin": ["administrators", "maintenance"],
    "system_admin": ["dashboard", "service", "device", "sessions", "maintenance"],
    "security_admin": ["keys", "testing"],
    "audit_admin": ["audit"],
}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
BACKUP_ID_RE = re.compile(r"^[0-9a-f]{32}$")
login_lock = threading.Lock()
login_failures: dict[str, list[float]] = {}
state_lock = threading.RLock()
password_salt_lock = threading.Lock()
password_salt_tickets: dict[str, dict[str, Any]] = {}
maintenance_lock = threading.Lock()
maintenance_active = threading.Event()
service_control_lock = threading.Lock()


class DaemonError(RuntimeError):
    def __init__(
        self, status: int, message: str = "密码服务调用失败", command: int | None = None,
    ) -> None:
        self.status = status
        self.command = command
        super().__init__(f"{message}（SDF 状态 0x{status:08x}）")


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("密码服务提前关闭连接")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class ProtocolClient:
    def __init__(self) -> None:
        self.host = os.getenv("SDFX_DAEMON_HOST", "127.0.0.1")
        self.port = int(os.getenv("SDFX_DAEMON_PORT", "18081"))

    def send(self, command: int, body: bytes = b"") -> bytes:
        header = struct.pack(
            "!8I", MAGIC, VERSION, command, len(body), 0, 0, 0, 0
        )
        with socket.create_connection((self.host, self.port), timeout=3) as sock:
            sock.settimeout(5)
            sock.sendall(header + body)
            raw_header = recv_exact(sock, 32)
            magic, version, returned_cmd, length, _, status, _, _ = struct.unpack(
                "!8I", raw_header
            )
            if magic != MAGIC or version != VERSION or returned_cmd != command:
                raise ConnectionError("密码服务返回了无效协议头")
            if length > 65504:
                raise ConnectionError("密码服务返回长度超限")
            payload = recv_exact(sock, length)
        if status != SDR_OK:
            raise DaemonError(status, command=command)
        return payload

    def admin(
        self,
        command: int,
        params: tuple[int, int, int, int] = (0, 0, 0, 0),
        secret: bytes = b"",
    ) -> bytes:
        token = TOKEN_FILE.read_bytes()
        if len(token) != 32:
            raise ConnectionError("管理令牌不可用")
        data = token + secret
        body = struct.pack("!QQ5I", 0, 0, *params, len(data)) + data
        payload = self.send(command, body)
        if len(payload) < 28:
            raise ConnectionError("密码服务返回了无效管理响应")
        _, _, _, _, _, data_len = struct.unpack("!Q5I", payload[:28])
        if data_len != len(payload) - 28:
            raise ConnectionError("密码服务管理响应长度不一致")
        return payload[28:]

    def status(self) -> dict[str, Any]:
        return json.loads(self.admin(CMD_ADMIN_STATUS))

    def keys(self) -> list[dict[str, Any]]:
        keys = json.loads(self.admin(CMD_ADMIN_KEY_LIST))
        keys.extend(json.loads(self.admin(CMD_ADMIN_RSA_KEY_LIST)))
        return sorted(keys, key=lambda item: (item["index"], item["type"], item["algorithm"]))

    def keks(self) -> list[dict[str, Any]]:
        return json.loads(self.admin(CMD_ADMIN_KEK_LIST))

    def backups(self) -> list[dict[str, Any]]:
        return json.loads(self.admin(CMD_ADMIN_BACKUP_LIST))

    def selftest(self) -> dict[str, Any]:
        return json.loads(self.admin(CMD_ADMIN_SELFTEST))

    def configure_device(self, vendor: str, device_name: str, serial: str) -> None:
        fields = [vendor.encode("utf-8"), device_name.encode("utf-8"), serial.encode("utf-8")]
        self.admin(
            CMD_ADMIN_DEVICE_CONFIG,
            (len(fields[0]), len(fields[1]), len(fields[2]), 0),
            b"".join(fields),
        )

    def sessions(self) -> list[dict[str, Any]]:
        return json.loads(self.admin(CMD_ADMIN_SESSION_LIST))

    def random(self, length: int) -> bytes:
        device_payload = self.send(CMD_OPEN_DEVICE, struct.pack("!I16s", 0, b""))
        if len(device_payload) != 8:
            raise ConnectionError("打开设备响应无效")
        device = struct.unpack("!Q", device_payload)[0]
        session = 0
        try:
            session_payload = self.send(CMD_OPEN_SESSION, struct.pack("!Q", device))
            if len(session_payload) != 8:
                raise ConnectionError("打开会话响应无效")
            session = struct.unpack("!Q", session_payload)[0]
            random_payload = self.send(
                CMD_GENERATE_RANDOM, struct.pack("!QI", session, length)
            )
            if len(random_payload) < 4:
                raise ConnectionError("随机数响应无效")
            actual = struct.unpack("!I", random_payload[:4])[0]
            if actual != length or len(random_payload) != 4 + actual:
                raise ConnectionError("随机数响应长度不一致")
            return random_payload[4:]
        finally:
            if session:
                try:
                    self.send(CMD_CLOSE_SESSION, struct.pack("!Q", session))
                except Exception:
                    pass
            try:
                self.send(CMD_CLOSE_DEVICE, struct.pack("!Q", device))
            except Exception:
                pass

    @staticmethod
    def _ecc_public_key(x: bytes, y: bytes) -> bytes:
        if len(x) != 32 or len(y) != 32:
            raise ValueError("SM2 公钥坐标必须为 32 字节")
        return struct.pack("=I", 256) + (b"\0" * 32) + x + (b"\0" * 32) + y

    def _open_crypto_session(self) -> tuple[int, int]:
        device_payload = self.send(CMD_OPEN_DEVICE, struct.pack("!I16s", 0, b""))
        if len(device_payload) != 8:
            raise ConnectionError("打开设备响应无效")
        device = struct.unpack("!Q", device_payload)[0]
        try:
            session_payload = self.send(CMD_OPEN_SESSION, struct.pack("!Q", device))
            if len(session_payload) != 8:
                raise ConnectionError("打开会话响应无效")
            return device, struct.unpack("!Q", session_payload)[0]
        except Exception:
            try:
                self.send(CMD_CLOSE_DEVICE, struct.pack("!Q", device))
            except Exception:
                pass
            raise

    def _close_crypto_session(self, device: int, session: int) -> None:
        try:
            self.send(CMD_CLOSE_SESSION, struct.pack("!Q", session))
        finally:
            self.send(CMD_CLOSE_DEVICE, struct.pack("!Q", device))

    def sm2_digest(self, x: bytes, y: bytes, message: bytes,
                   identity: bytes = UKEY_SM2_ID) -> bytes:
        if not message or len(message) > 32768:
            raise ValueError("SM2 消息长度必须为 1–32768 字节")
        public_key = self._ecc_public_key(x, y)
        device, session = self._open_crypto_session()
        try:
            self.send(
                CMD_HASH_INIT,
                struct.pack("!QI", session, 1) + public_key
                + struct.pack("!I", len(identity)) + identity,
            )
            self.send(
                CMD_HASH_UPDATE,
                struct.pack("!QI", session, len(message)) + message,
            )
            payload = self.send(CMD_HASH_FINAL, struct.pack("!Q", session))
            if len(payload) < 4:
                raise ConnectionError("SM2 摘要响应无效")
            length = struct.unpack("!I", payload[:4])[0]
            if length != 32 or len(payload) < 4 + length:
                raise ConnectionError("SM2 摘要响应长度无效")
            return payload[4:4 + length]
        finally:
            self._close_crypto_session(device, session)

    def sm2_verify_digest(self, x: bytes, y: bytes, digest: bytes,
                          signature: bytes) -> bool:
        if len(digest) != 32 or len(signature) != 64:
            return False
        public_key = self._ecc_public_key(x, y)
        device, session = self._open_crypto_session()
        try:
            payload = self.send(
                CMD_EXTERNAL_VERIFY_ECC,
                struct.pack("!QI", session, 0x00020200) + public_key
                + struct.pack("!II", len(digest), len(signature))
                + digest + signature,
            )
            if len(payload) != 4:
                raise ConnectionError("SM2 验签响应无效")
            return struct.unpack("!I", payload)[0] == 0
        finally:
            self._close_crypto_session(device, session)

    def sm2_message_verify(self, x: bytes, y: bytes, message: bytes,
                           signature: bytes) -> bool:
        digest = self.sm2_digest(x, y, message, UKEY_SM2_ID)
        return self.sm2_verify_digest(x, y, digest, signature)


protocol = ProtocolClient()


class SupervisorUnixConnection(http.client.HTTPConnection):
    """HTTP connection transported over Supervisor's private Unix socket."""

    def __init__(self, socket_path: Path) -> None:
        # sdfxd may need Supervisor's full graceful-stop window before replying.
        super().__init__("localhost", timeout=15)
        self.socket_path = socket_path

    def connect(self) -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        connection.connect(str(self.socket_path))
        self.sock = connection


class SupervisorUnixTransport(xmlrpc.client.Transport):
    def __init__(self, socket_path: Path) -> None:
        super().__init__()
        self.socket_path = socket_path

    def make_connection(self, host: str) -> SupervisorUnixConnection:
        return SupervisorUnixConnection(self.socket_path)


class ServiceSupervisor:
    process_name = "sdfxd"

    def _call(self, method: str, *args: Any) -> Any:
        transport = SupervisorUnixTransport(SUPERVISOR_SOCKET)
        proxy = xmlrpc.client.ServerProxy(
            "http://localhost/RPC2",
            transport=transport,
            allow_none=True,
        )
        try:
            return getattr(proxy.supervisor, method)(*args)
        except xmlrpc.client.Fault as error:
            conflict_codes = {60, 70}
            status_code = 409 if error.faultCode in conflict_codes else 503
            raise HTTPException(
                status_code,
                f"密码服务进程控制失败：{error.faultString}",
            ) from error
        except (OSError, http.client.HTTPException, xmlrpc.client.ProtocolError) as error:
            raise ConnectionError(f"无法连接容器进程管理器：{error}") from error
        finally:
            transport.close()

    def info(self) -> dict[str, Any]:
        return self._call("getProcessInfo", self.process_name)

    def start(self) -> None:
        self._call("startProcess", self.process_name, True)

    def stop(self) -> None:
        self._call("stopProcess", self.process_name, True)


service_supervisor = ServiceSupervisor()


def service_snapshot(include_daemon: bool = True) -> dict[str, Any]:
    info = service_supervisor.info()
    supervisor_state = str(info.get("statename", "UNKNOWN")).upper()
    running = supervisor_state == "RUNNING"
    daemon: dict[str, Any] | None = None
    daemon_error: str | None = None
    if running and include_daemon:
        try:
            daemon = protocol.status()
        except (DaemonError, ConnectionError, OSError, json.JSONDecodeError) as error:
            daemon_error = str(error)

    started_at = int(info.get("start") or 0)
    now = int(info.get("now") or time.time())
    return {
        "name": service_supervisor.process_name,
        "display_name": "SDF 密码服务",
        "supervisor_state": supervisor_state,
        "running": running,
        "daemon_available": daemon is not None,
        "listen_host": DAEMON_LISTEN_HOST,
        "port": protocol.port,
        "address": f"{DAEMON_LISTEN_HOST}:{protocol.port}",
        "started_at": started_at or None,
        "stopped_at": int(info.get("stop") or 0) or None,
        "uptime_seconds": max(0, now - started_at) if running and started_at else 0,
        "pid": int(info.get("pid") or 0) or None,
        "description": str(info.get("description") or ""),
        "spawn_error": str(info.get("spawnerr") or ""),
        "total_requests": daemon.get("total_requests") if daemon else None,
        "active_sessions": daemon.get("active_sessions") if daemon else None,
        "keys": daemon.get("keys") if daemon else None,
        "daemon_error": daemon_error,
    }


def atomic_json_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def load_state() -> dict[str, Any] | None:
    try:
        with STATE_FILE.open("r", encoding="utf-8") as stream:
            state = json.load(stream)
        if not isinstance(state, dict):
            return None
        if "users" not in state and isinstance(state.get("admin"), dict):
            legacy = state.pop("admin")
            username = legacy.get("username")
            if isinstance(username, str) and isinstance(legacy.get("password"), dict):
                state["users"] = {
                    username: {
                        "role": "super_admin",
                        "enabled": True,
                        "password": legacy["password"],
                        "created_at": int(state.get("initialized_at", time.time())),
                    }
                }
                state["version"] = 2
                atomic_json_write(STATE_FILE, state)
        migrated_login_mode = False
        users = state.get("users")
        if isinstance(users, dict):
            for user in users.values():
                if isinstance(user, dict) and user.get("login_mode") == "ukey_only":
                    user["login_mode"] = "password"
                    migrated_login_mode = True
        if migrated_login_mode:
            atomic_json_write(STATE_FILE, state)
        return state
    except FileNotFoundError:
        return None


def decode_password_hash(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise HTTPException(422, "口令 SM3 哈希格式无效") from error
    if len(decoded) != PASSWORD_HASH_BYTES:
        raise HTTPException(422, "口令 SM3 哈希必须为 32 字节")
    return decoded


def password_record_values(record: dict[str, Any]) -> tuple[bytes, bytes] | None:
    try:
        salt = base64.b64decode(record["salt"], validate=True)
        expected = base64.b64decode(record["hash"], validate=True)
        if len(salt) != PASSWORD_SALT_BYTES or len(expected) != PASSWORD_HASH_BYTES:
            return None
        return salt, expected
    except (KeyError, ValueError, TypeError):
        return None


def issue_password_salt(
    username: str, issued_by: str, *, preserve_existing: bool = False
) -> dict[str, str | int]:
    now = int(time.time())
    state = load_state() or {}
    used_salts: set[bytes] = set()
    existing_salt: bytes | None = None
    users = state.get("users", {})
    if isinstance(users, dict):
        for stored_username, user in users.items():
            if isinstance(user, dict):
                values = password_record_values(user.get("password", {}))
                if values is not None:
                    used_salts.add(values[0])
                    if preserve_existing and stored_username == username:
                        existing_salt = values[0]
    with password_salt_lock:
        expired = [key for key, value in password_salt_tickets.items()
                   if int(value["expires_at"]) < now]
        for key in expired:
            password_salt_tickets.pop(key, None)
        used_salts.update(value["salt"] for value in password_salt_tickets.values())
        salt = existing_salt or b""
        if existing_salt is None:
            for _ in range(16):
                candidate = protocol.random(PASSWORD_SALT_BYTES)
                if candidate not in used_salts:
                    salt = candidate
                    break
        if len(salt) != PASSWORD_SALT_BYTES:
            raise HTTPException(503, "无法生成唯一的账户口令盐值")
        ticket_id = secrets.token_urlsafe(24)
        expires_at = now + PASSWORD_SALT_TICKET_TTL
        password_salt_tickets[ticket_id] = {
            "username": username,
            "issued_by": issued_by,
            "salt": salt,
            "expires_at": expires_at,
        }
    return {
        "ticket_id": ticket_id,
        "salt_base64": base64.b64encode(salt).decode("ascii"),
        "expires_at": expires_at,
    }


def consume_password_salt(ticket_id: str, username: str, issued_by: str) -> bytes:
    now = int(time.time())
    with password_salt_lock:
        ticket = password_salt_tickets.pop(ticket_id, None)
    if (
        not isinstance(ticket, dict)
        or ticket.get("username") != username
        or ticket.get("issued_by") != issued_by
        or int(ticket.get("expires_at", 0)) < now
        or not isinstance(ticket.get("salt"), bytes)
        or len(ticket["salt"]) != PASSWORD_SALT_BYTES
    ):
        raise HTTPException(409, "账户口令盐值凭据无效或已过期，请重新提交")
    return ticket["salt"]


def password_record(material: "PasswordHashInput", username: str, issued_by: str) -> dict[str, str]:
    if not material.ticket_id:
        raise HTTPException(422, "创建或修改口令时缺少盐值凭据")
    salt = consume_password_salt(material.ticket_id, username, issued_by)
    digest = decode_password_hash(material.hash_base64)
    return {
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": base64.b64encode(digest).decode("ascii"),
    }


def verify_password(material: "PasswordHashInput", record: dict[str, Any]) -> bool:
    values = password_record_values(record)
    if values is None:
        return False
    try:
        actual = decode_password_hash(material.hash_base64)
    except HTTPException:
        return False
    return hmac.compare_digest(actual, values[1])


def db() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_FILE, timeout=5)
    connection.row_factory = sqlite3.Row
    return connection


def lifecycle_id(algorithm: str, key_type: str, index: int) -> str:
    normalized = "SM4" if key_type == "kek" else key_algorithm(algorithm)
    return f"{normalized.lower()}:{key_type}:{index}"


def validate_validity_days(validity_days: int) -> None:
    if validity_days < 0 or validity_days > 36500:
        raise HTTPException(422, "密钥有效期必须为 0–36500 天，0 表示长期有效")


def save_key_lifecycle(
    algorithm: str, key_type: str, index: int, validity_days: int,
    *, created_at: int | None = None,
) -> None:
    validate_validity_days(validity_days)
    now = int(time.time())
    created = now if created_at is None else int(created_at)
    expires = None if validity_days == 0 else created + validity_days * 86400
    with db() as connection:
        connection.execute(
            """
            INSERT INTO key_lifecycle(key_id, created_at, expires_at, validity_days, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(key_id) DO UPDATE SET
                expires_at=excluded.expires_at,
                validity_days=excluded.validity_days,
                updated_at=excluded.updated_at
            """,
            (lifecycle_id(algorithm, key_type, index), created, expires, validity_days, now),
        )


def delete_key_lifecycle(algorithm: str, key_type: str, index: int) -> None:
    with db() as connection:
        connection.execute(
            "DELETE FROM key_lifecycle WHERE key_id = ?",
            (lifecycle_id(algorithm, key_type, index),),
        )


def reindex_key_lifecycle(algorithm: str, key_type: str, old_index: int, new_index: int) -> None:
    with db() as connection:
        connection.execute(
            "UPDATE key_lifecycle SET key_id = ?, updated_at = ? WHERE key_id = ?",
            (
                lifecycle_id(algorithm, key_type, new_index), int(time.time()),
                lifecycle_id(algorithm, key_type, old_index),
            ),
        )


def attach_key_lifecycle(items: list[dict[str, Any]], key_type: str | None = None) -> list[dict[str, Any]]:
    with db() as connection:
        rows = {
            row["key_id"]: dict(row)
            for row in connection.execute("SELECT * FROM key_lifecycle").fetchall()
        }
    now = int(time.time())
    for item in items:
        item_type = key_type or str(item.get("type", ""))
        algorithm = "SM4" if item_type == "kek" else str(item.get("algorithm", "SM2"))
        key_id = lifecycle_id(algorithm, item_type, int(item["index"]))
        lifecycle = rows.get(key_id)
        created_at = int(item.get("created_at") or now)
        if lifecycle is None:
            save_key_lifecycle(algorithm, item_type, int(item["index"]), 0, created_at=created_at)
            lifecycle = {
                "created_at": created_at, "expires_at": None,
                "validity_days": 0, "updated_at": created_at,
            }
        expires_at = lifecycle.get("expires_at")
        remaining_days = None if expires_at is None else math.ceil((int(expires_at) - now) / 86400)
        expiry_status = (
            "permanent" if expires_at is None else
            "expired" if remaining_days <= 0 else
            "warning" if remaining_days <= 30 else "valid"
        )
        item.update({
            "lifecycle_created_at": int(lifecycle["created_at"]),
            "validity_days": int(lifecycle["validity_days"]),
            "expires_at": None if expires_at is None else int(expires_at),
            "remaining_days": remaining_days,
            "expiry_status": expiry_status,
        })
    active_ids = {
        lifecycle_id(
            "SM4" if (key_type or str(item.get("type", ""))) == "kek"
            else str(item.get("algorithm", "SM2")),
            key_type or str(item.get("type", "")), int(item["index"]),
        )
        for item in items
    }
    known_prefixes = ("sm4:kek:",) if key_type == "kek" else ("sm2:sign:", "sm2:enc:", "rsa:sign:", "rsa:enc:")
    stale_ids = [key_id for key_id in rows if key_id.startswith(known_prefixes) and key_id not in active_ids]
    if stale_ids:
        with db() as connection:
            connection.executemany(
                "DELETE FROM key_lifecycle WHERE key_id = ?",
                ((key_id,) for key_id in stale_ids),
            )
    return items


def initialize_storage() -> None:
    WEB_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(WEB_ROOT, 0o700)
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_ROOT, 0o700)
    with db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                csrf TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at INTEGER NOT NULL,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                result TEXT NOT NULL,
                remote_addr TEXT NOT NULL
            )
            """
        )
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(audit)").fetchall()
        }
        additions = {
            "level": "TEXT NOT NULL DEFAULT 'INFO'",
            "category": "TEXT NOT NULL DEFAULT 'management'",
            "request_id": "TEXT NOT NULL DEFAULT ''",
            "method": "TEXT NOT NULL DEFAULT ''",
            "path": "TEXT NOT NULL DEFAULT ''",
            "details": "TEXT NOT NULL DEFAULT ''",
            "user_agent": "TEXT NOT NULL DEFAULT ''",
        }
        for name, declaration in additions.items():
            if name not in columns:
                connection.execute(f"ALTER TABLE audit ADD COLUMN {name} {declaration}")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS manager_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ukey_challenges (
                challenge_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                flow_hash TEXT NOT NULL,
                message BLOB NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS key_lifecycle (
                key_id TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                validity_days INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT OR IGNORE INTO manager_settings(key, value) VALUES (?, ?)",
            ("audit_retention_days", "365"),
        )
        connection.execute(
            "INSERT OR IGNORE INTO manager_settings(key, value) VALUES (?, ?)",
            ("audit_display_level", "INFO"),
        )
        connection.execute(
            "DELETE FROM sessions WHERE expires_at < ?", (int(time.time()),)
        )
        connection.execute(
            "DELETE FROM ukey_challenges WHERE expires_at < ?", (int(time.time()) - 300,)
        )
    os.chmod(DATABASE_FILE, 0o600)


initialize_storage()
app = FastAPI(title=PRODUCT_NAME, docs_url=None, redoc_url=None)


class PasswordHashInput(BaseModel):
    hash_base64: str
    ticket_id: str | None = None


class PasswordSaltRequest(BaseModel):
    username: str


class InitializeRequest(BaseModel):
    username: str
    password: PasswordHashInput
    vendor: str = "SDFX Project"
    device_name: str = "SDFX-1.1.4"
    serial: str = "SW000001"



class LoginRequest(BaseModel):
    username: str
    password: PasswordHashInput


class UKeyChallengeRequest(BaseModel):
    username: str
    password: PasswordHashInput


class UKeyVerifyRequest(BaseModel):
    username: str
    challenge_id: str
    signature_base64url: str
    certificate_base64: str
    digest_base64url: str | None = None


class UKeyBindingRequest(BaseModel):
    enabled: bool = True
    user_certificate_base64: str
    ca_certificate_base64: str


class DeviceUpdate(BaseModel):
    vendor: str
    device_name: str
    serial: str


class KeyCreateRequest(BaseModel):
    type: str
    index: int
    algorithm: str = "SM2"
    bits: int | None = None
    password: str = ""
    validity_days: int = 365


class KekCreateRequest(BaseModel):
    index: int
    validity_days: int = 365


class KeyPasswordRequest(BaseModel):
    old_password: str = ""
    new_password: str = ""


class KeyReindexRequest(BaseModel):
    new_index: int


class KeyValidityRequest(BaseModel):
    validity_days: int = 365


class UserCreateRequest(BaseModel):
    username: str
    password: PasswordHashInput
    role: str


class UserUpdateRequest(BaseModel):
    password: PasswordHashInput | None = None
    role: str | None = None
    enabled: bool | None = None
    login_mode: str | None = None


class ConfirmRequest(BaseModel):
    password: PasswordHashInput
    confirmation: str


class BackupRestoreRequest(BaseModel):
    backup_id: str
    password: PasswordHashInput
    confirmation: str


class ResetRequest(BaseModel):
    password: PasswordHashInput
    serial: str
    confirmation: str


class AuditSettingsUpdate(BaseModel):
    retention_days: int
    display_level: str


class ServiceControlRequest(BaseModel):
    confirmation: str


def validate_metadata(vendor: str, device_name: str, serial: str) -> None:
    values = ((vendor, 40, "厂商"), (device_name, 16, "设备名"), (serial, 16, "序列号"))
    for value, maximum, label in values:
        encoded = value.encode("utf-8")
        if not value.strip() or len(encoded) > maximum:
            raise HTTPException(422, f"{label}必须为 1–{maximum} 字节")


def remote_addr(request: Request) -> str:
    return request.client.host if request.client else "local"


def audit(
    request: Request,
    username: str,
    action: str,
    target: str,
    result: str,
    *,
    level: str = "INFO",
    category: str = "management",
    details: str = "",
) -> None:
    with db() as connection:
        connection.execute(
            """
            INSERT INTO audit(
                occurred_at, username, action, target, result, remote_addr,
                level, category, request_id, method, path, details, user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(time.time()), username, action, target, result, remote_addr(request),
                level, category, getattr(request.state, "request_id", ""),
                request.method, request.url.path, details[:512],
                request.headers.get("user-agent", "")[:256],
            ),
        )


AUDIT_LEVEL_ORDER = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}
AUDIT_EXPORT_FORMATS = {"txt", "csv", "jsonl"}
AUDIT_EXPORT_FIELDS = (
    "occurred_at", "level", "category", "username", "action", "target",
    "result", "remote_addr", "request_id", "method", "path", "details",
    "user_agent",
)


def request_username(request: Request) -> str:
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        return "anonymous"
    try:
        with db() as connection:
            row = connection.execute(
                "SELECT username FROM sessions WHERE id_hash = ?", (session_hash(raw),)
            ).fetchone()
        return str(row["username"]) if row else "anonymous"
    except (OSError, sqlite3.Error):
        return "anonymous"


def audit_sdf_failure(request: Request, error: Exception, code: str) -> None:
    command = getattr(error, "command", None)
    command_text = f"0x{command:04X}" if isinstance(command, int) else "unknown"
    status = getattr(error, "status", None)
    status_text = f"0x{status:08X}" if isinstance(status, int) else "unavailable"
    try:
        audit(
            request,
            request_username(request),
            "sdf_call_failed",
            f"command:{command_text}",
            "failure",
            level="ERROR",
            category="sdf",
            details=f"code={code};status={status_text};error={error}",
        )
    except (OSError, sqlite3.Error):
        pass


def read_audit_settings() -> dict[str, Any]:
    with db() as connection:
        values = {row["key"]: row["value"] for row in connection.execute(
            "SELECT key, value FROM manager_settings"
        ).fetchall()}
    try:
        retention_days = int(values.get("audit_retention_days", "365"))
    except ValueError:
        retention_days = 365
    display_level = values.get("audit_display_level", "INFO").upper()
    if display_level not in AUDIT_LEVEL_ORDER:
        display_level = "INFO"
    return {"retention_days": max(1, min(retention_days, 3650)), "display_level": display_level}


def session_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def create_session(response: Response, username: str) -> str:
    raw = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    expires = int(time.time()) + SESSION_TTL
    with db() as connection:
        connection.execute(
            "INSERT INTO sessions(id_hash, username, csrf, expires_at) VALUES (?, ?, ?, ?)",
            (session_hash(raw), username, csrf, expires),
        )
    response.set_cookie(
        COOKIE_NAME,
        raw,
        max_age=SESSION_TTL,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return csrf


def current_session(request: Request) -> dict[str, Any]:
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        raise HTTPException(401, "请先登录")
    with db() as connection:
        row = connection.execute(
            "SELECT username, csrf, expires_at FROM sessions WHERE id_hash = ?",
            (session_hash(raw),),
        ).fetchone()
        if row is None or row["expires_at"] < int(time.time()):
            connection.execute(
                "DELETE FROM sessions WHERE id_hash = ?", (session_hash(raw),)
            )
            raise HTTPException(401, "会话已过期")
        expires = int(time.time()) + SESSION_TTL
        connection.execute(
            "UPDATE sessions SET expires_at = ? WHERE id_hash = ?",
            (expires, session_hash(raw)),
        )
    state = require_initialized()
    user = state.get("users", {}).get(row["username"])
    if not isinstance(user, dict) or not user.get("enabled", True):
        with db() as connection:
            connection.execute(
                "DELETE FROM sessions WHERE id_hash = ?", (session_hash(raw),)
            )
        raise HTTPException(403, "管理员账户已停用或删除")
    role = user.get("role")
    if role not in ROLES:
        raise HTTPException(403, "管理员角色无效")
    return {
        "username": row["username"],
        "role": role,
        "role_label": ROLE_LABELS[role],
        "pages": ROLE_PAGES[role],
        "csrf": row["csrf"],
        "expires_at": expires,
    }


def csrf_session(
    request: Request, x_csrf_token: str | None = Header(default=None)
) -> dict[str, Any]:
    session = current_session(request)
    if not x_csrf_token or not hmac.compare_digest(x_csrf_token, session["csrf"]):
        raise HTTPException(403, "CSRF 校验失败")
    return session


def require_roles(*roles: str, csrf: bool = False):
    source = csrf_session if csrf else current_session

    def dependency(session: dict[str, Any] = Depends(source)) -> dict[str, Any]:
        if session["role"] not in roles:
            raise HTTPException(403, "当前管理员无权执行此操作")
        return session

    return dependency


def verify_session_password(password: PasswordHashInput, session: dict[str, Any]) -> bool:
    state = require_initialized()
    user = state.get("users", {}).get(session["username"], {})
    return isinstance(user, dict) and verify_password(password, user.get("password", {}))


def require_initialized() -> dict[str, Any]:
    state = load_state()
    if state is None:
        raise HTTPException(409, "设备尚未初始化")
    return state


def certificate_chain_check(
    ca_x: bytes, ca_y: bytes, message: bytes, signature: bytes,
) -> bool:
    digest = protocol.sm2_digest(ca_x, ca_y, message, UKEY_SM2_ID)
    return protocol.sm2_verify_digest(ca_x, ca_y, digest, signature)


def validate_ukey_binding(
    user_certificate_base64: str,
    ca_certificate_base64: str,
) -> tuple[bytes, bytes, dict[str, Any]]:
    try:
        user_der = decode_certificate(user_certificate_base64)
        ca_der = decode_certificate(ca_certificate_base64)
        summary = validate_certificate_binding(
            user_der,
            ca_der,
            certificate_chain_check,
        )
        return user_der, ca_der, summary
    except UKeyCertificateError as error:
        raise HTTPException(422, str(error)) from error


def public_ukey_binding(user: dict[str, Any]) -> dict[str, Any] | None:
    binding = user.get("ukey_auth")
    if not isinstance(binding, dict):
        return None
    return {
        "enabled": bool(binding.get("enabled", False)),
        "configured_at": binding.get("configured_at"),
        "configured_by": binding.get("configured_by"),
        "revocation_mode": binding.get("revocation_mode", "off"),
        "trust_mode": "uploaded_ca_anchor",
        "validation": binding.get("validation", {}),
    }


def user_login_mode(user: dict[str, Any]) -> str:
    mode = user.get("login_mode", "password")
    if mode == "ukey_only":
        return "password"
    return mode if mode in LOGIN_MODES else "password"


def require_ukey_user(username: str) -> tuple[dict[str, Any], dict[str, Any]]:
    state = require_initialized()
    user = state.get("users", {}).get(username)
    binding = user.get("ukey_auth") if isinstance(user, dict) else None
    if (
        not isinstance(user, dict)
        or not user.get("enabled", True)
        or not isinstance(binding, dict)
        or not binding.get("enabled", False)
        or user_login_mode(user) != "password_ukey"
    ):
        raise HTTPException(401, "用户名或 UKey 身份配置无效")
    return user, binding


def key_params(key_type: str, index: int) -> tuple[int, int, int, int]:
    if key_type not in KEY_TYPES or index < 1 or index > 1024:
        raise HTTPException(422, "密钥类型或索引无效")
    return KEY_TYPES[key_type], index, 0, 0


def key_algorithm(value: str) -> str:
    algorithm = value.strip().upper()
    if algorithm not in {"SM2", "RSA"}:
        raise HTTPException(422, "仅支持 SM2 或 RSA 密钥")
    return algorithm


def key_admin_command(algorithm: str, sm2_command: int, rsa_command: int) -> int:
    return rsa_command if key_algorithm(algorithm) == "RSA" else sm2_command


def backup_path(backup_id: str) -> Path:
    if not BACKUP_ID_RE.fullmatch(backup_id):
        raise HTTPException(422, "备份编号无效")
    return BACKUP_ROOT / f"{backup_id}.sdfxbak"


@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", secrets.token_hex(8))[:64]
    request.state.request_id = request_id
    try:
        if maintenance_active.is_set() and request.url.path != "/api/health":
            response = Response(
                json.dumps({"error": {"code": "maintenance", "message": "设备正在执行维护操作"}}, ensure_ascii=False),
                status_code=503, media_type="application/json",
            )
        else:
            response = await call_next(request)
    except DaemonError as error:
        audit_sdf_failure(request, error, "sdf_error")
        response = Response(
            json.dumps(
                {"error": {"code": "sdf_error", "message": str(error)}, "request_id": request_id},
                ensure_ascii=False,
            ),
            status_code=502,
            media_type="application/json",
        )
    except (ConnectionError, OSError, json.JSONDecodeError) as error:
        audit_sdf_failure(request, error, "daemon_unavailable")
        response = Response(
            json.dumps(
                {"error": {"code": "daemon_unavailable", "message": str(error)}, "request_id": request_id},
                ensure_ascii=False,
            ),
            status_code=503,
            media_type="application/json",
        )
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/health")
def health() -> dict[str, Any]:
    service = service_snapshot()
    return {
        "status": "ok",
        "product": PRODUCT_NAME,
        "version": PRODUCT_VERSION,
        "initialized": load_state() is not None,
        "daemon": service,
    }


@app.post("/api/auth/initialize-password-salt")
def initialize_password_salt(payload: PasswordSaltRequest) -> dict[str, str | int]:
    if load_state() is not None:
        raise HTTPException(409, "设备已经初始化")
    if not USERNAME_RE.fullmatch(payload.username):
        raise HTTPException(422, "用户名仅允许 3–32 位字母、数字、点、横线和下划线")
    return issue_password_salt(payload.username, "")


@app.get("/api/auth/password-salt")
def get_password_salt(username: str) -> dict[str, str]:
    state = require_initialized()
    user = state.get("users", {}).get(username)
    values = password_record_values(user.get("password", {})) if isinstance(user, dict) else None
    if values is None or not user.get("enabled", True):
        raise HTTPException(401, "用户名或账户口令格式无效")
    return {"salt_base64": base64.b64encode(values[0]).decode("ascii")}


@app.post("/api/initialize", status_code=201)
def initialize(payload: InitializeRequest, request: Request) -> dict[str, Any]:
    if load_state() is not None:
        raise HTTPException(409, "设备已经初始化")
    if not USERNAME_RE.fullmatch(payload.username):
        raise HTTPException(422, "用户名仅允许 3–32 位字母、数字、点、横线和下划线")
    validate_metadata(payload.vendor, payload.device_name, payload.serial)
    stored_password = password_record(payload.password, payload.username, "")

    protocol.admin(CMD_ADMIN_INTEGRITY_INIT)
    protocol.configure_device(
        payload.vendor.strip(), payload.device_name.strip(), payload.serial.strip()
    )
    state = {
        "version": 2,
        "initialized_at": int(time.time()),
        "users": {
            payload.username: {
                "role": "super_admin",
                "enabled": True,
                "login_mode": "password",
                "password": stored_password,
                "created_at": int(time.time()),
            }
        },
        "device": {
            "vendor": payload.vendor.strip(),
            "device_name": payload.device_name.strip(),
            "serial": payload.serial.strip(),
        },
    }
    atomic_json_write(STATE_FILE, state)
    with db() as connection:
        connection.execute("DELETE FROM sessions")
        connection.execute("DELETE FROM ukey_challenges")
    audit(
        request, payload.username, "system_initialize", "device", "success",
        category="system", details="created super administrator and device integrity key",
    )
    return {"initialized": True, "next_step": "create_administrators"}

@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, Any]:
    state = require_initialized()
    address = remote_addr(request)
    now = time.time()
    with login_lock:
        attempts = [item for item in login_failures.get(address, []) if now - item < 900]
        login_failures[address] = attempts
        if len(attempts) >= 5:
            raise HTTPException(429, "登录失败次数过多，请 15 分钟后再试")

    user = state.get("users", {}).get(payload.username)
    valid = isinstance(user, dict) and user.get("enabled", True)
    valid = valid and user_login_mode(user) == "password"
    valid = valid and verify_password(payload.password, user.get("password", {}))
    if not valid:
        with login_lock:
            login_failures.setdefault(address, []).append(now)
        audit(request, payload.username[:32], "login", "manager", "failure")
        raise HTTPException(401, "用户名、密码或账户登录方式不正确")

    with login_lock:
        login_failures.pop(address, None)
    csrf = create_session(response, payload.username)
    audit(request, payload.username, "login", "manager", "success")
    return {"username": payload.username, "role": user["role"], "role_label": ROLE_LABELS[user["role"]], "pages": ROLE_PAGES[user["role"]], "csrf": csrf, "expires_in": SESSION_TTL}


@app.post("/api/auth/ukey/challenge")
def create_ukey_challenge(
    payload: UKeyChallengeRequest,
    request: Request,
    response: Response,
) -> dict[str, Any]:
    address = remote_addr(request)
    now_float = time.time()
    with login_lock:
        attempts = [item for item in login_failures.get(address, []) if now_float - item < 900]
        login_failures[address] = attempts
        if len(attempts) >= 5:
            raise HTTPException(429, "登录失败次数过多，请 15 分钟后再试")
    user, _ = require_ukey_user(payload.username)
    login_mode = user_login_mode(user)
    password_valid = verify_password(payload.password, user.get("password", {}))
    if not password_valid:
        with login_lock:
            login_failures.setdefault(address, []).append(now_float)
        audit(
            request, payload.username[:32], "ukey_challenge_create", "manager",
            "failure", level="WARN", category="access",
            details="password factor failed for password_ukey mode",
        )
        raise HTTPException(401, "用户名、登录密码或账户登录方式不正确")

    now = int(now_float)
    expires_at = now + UKEY_CHALLENGE_TTL
    challenge_id = secrets.token_urlsafe(24)
    flow_token = secrets.token_urlsafe(32)
    nonce = protocol.random(32)
    signed_object = {
        "version": "1",
        "purpose": "cryptokit-soft-hsm-manager-login",
        "username": payload.username,
        "login_mode": login_mode,
        "session_id": flow_token,
        "nonce": base64url_encode(nonce),
        "issued_at": now,
        "expires_at": expires_at,
    }
    message = json.dumps(
        signed_object, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    with db() as connection:
        connection.execute("DELETE FROM ukey_challenges WHERE expires_at < ?", (now,))
        connection.execute(
            """
            INSERT INTO ukey_challenges(
                challenge_id, username, flow_hash, message, issued_at, expires_at, used
            ) VALUES (?, ?, ?, ?, ?, ?, 0)
            """,
            (challenge_id, payload.username, session_hash(flow_token), message, now, expires_at),
        )
    response.set_cookie(
        UKEY_FLOW_COOKIE_NAME,
        flow_token,
        max_age=UKEY_CHALLENGE_TTL,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/api/auth/ukey",
    )
    audit(
        request, payload.username, "ukey_challenge_create", "manager", "success",
        category="access", details=f"challenge_id={challenge_id[:12]};ttl={UKEY_CHALLENGE_TTL}",
    )
    return {
        "challenge_id": challenge_id,
        "challenge_base64url": base64url_encode(message),
        "expires_at": expires_at,
        "expires_in": UKEY_CHALLENGE_TTL,
        "sm2_user_id": UKEY_SM2_ID.decode("ascii"),
        "agent_endpoint": "http://127.0.0.1:18088",
    }


@app.post("/api/auth/ukey/verify")
def verify_ukey_login(
    payload: UKeyVerifyRequest,
    request: Request,
    response: Response,
) -> dict[str, Any]:
    user, binding = require_ukey_user(payload.username)
    login_mode = user_login_mode(user)
    flow_token = request.cookies.get(UKEY_FLOW_COOKIE_NAME, "")
    now = int(time.time())
    with db() as connection:
        row = connection.execute(
            """
            SELECT username, flow_hash, message, expires_at, used
            FROM ukey_challenges WHERE challenge_id = ?
            """,
            (payload.challenge_id,),
        ).fetchone()
    try:
        challenge_login_mode = json.loads(bytes(row["message"]).decode("utf-8")).get(
            "login_mode"
        ) if row is not None else None
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
        challenge_login_mode = None
    valid_challenge = (
        row is not None
        and row["username"] == payload.username
        and not row["used"]
        and int(row["expires_at"]) >= now
        and bool(flow_token)
        and hmac.compare_digest(row["flow_hash"], session_hash(flow_token))
        and challenge_login_mode == login_mode
    )
    if not valid_challenge:
        with login_lock:
            login_failures.setdefault(remote_addr(request), []).append(time.time())
        audit(
            request, payload.username[:32], "ukey_login", "manager", "failure",
            level="WARN", category="access", details="invalid, expired, used, or unbound challenge",
        )
        raise HTTPException(401, "UKey 登录挑战无效、已过期或已使用")

    try:
        configured_user_der, _, validation = validate_ukey_binding(
            binding["user_certificate_base64"],
            binding["ca_certificate_base64"],
        )
        presented_der = decode_certificate(payload.certificate_base64)
        if not hmac.compare_digest(
            hashlib.sha256(presented_der).digest(),
            hashlib.sha256(configured_user_der).digest(),
        ):
            raise UKeyCertificateError("UKey 返回证书与管理员绑定证书不一致")
        signature = base64url_decode(payload.signature_base64url)
        if len(signature) != 64:
            raise UKeyCertificateError("UKey 签名必须为 64 字节 r||s")
        message = bytes(row["message"])
        public_x, public_y = sm2_public_point(configured_user_der)
        digest = protocol.sm2_digest(public_x, public_y, message, UKEY_SM2_ID)
        if payload.digest_base64url is not None:
            agent_digest = base64url_decode(payload.digest_base64url)
            if not hmac.compare_digest(agent_digest, digest):
                raise UKeyCertificateError("UKey Agent 返回的消息摘要与密码机计算结果不一致")
        if not protocol.sm2_verify_digest(public_x, public_y, digest, signature):
            raise UKeyCertificateError("UKey 挑战签名验证失败")
    except UKeyCertificateError as error:
        with login_lock:
            login_failures.setdefault(remote_addr(request), []).append(time.time())
        audit(
            request, payload.username[:32], "ukey_login", "manager", "failure",
            level="WARN", category="access", details=str(error),
        )
        raise HTTPException(401, str(error)) from error

    with db() as connection:
        changed = connection.execute(
            "UPDATE ukey_challenges SET used = 1 WHERE challenge_id = ? AND used = 0",
            (payload.challenge_id,),
        ).rowcount
    if changed != 1:
        raise HTTPException(401, "UKey 登录挑战已经使用")

    with login_lock:
        login_failures.pop(remote_addr(request), None)
    csrf = create_session(response, payload.username)
    response.delete_cookie(UKEY_FLOW_COOKIE_NAME, path="/api/auth/ukey")
    audit(
        request, payload.username, "ukey_login", "manager", "success",
        category="access",
        details=(
            "certificate_sha256="
            + validation["user_certificate"]["sha256_fingerprint"]
        ),
    )
    return {
        "username": payload.username,
        "role": user["role"],
        "role_label": ROLE_LABELS[user["role"]],
        "pages": ROLE_PAGES[user["role"]],
        "csrf": csrf,
        "expires_in": SESSION_TTL,
        "authentication": "password-and-ukey-sm2-challenge",
    }


@app.get("/api/auth/session")
def session_info(session: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    return session


@app.post("/api/auth/logout")
def logout(
    request: Request,
    response: Response,
    session: dict[str, Any] = Depends(csrf_session),
) -> dict[str, bool]:
    raw = request.cookies.get(COOKIE_NAME)
    if raw:
        with db() as connection:
            connection.execute("DELETE FROM sessions WHERE id_hash = ?", (session_hash(raw),))
    response.delete_cookie(COOKIE_NAME, path="/")
    audit(request, session["username"], "logout", "manager", "success")
    return {"logged_out": True}


@app.get("/api/status")
def status(session: dict[str, Any] = Depends(require_roles("system_admin"))) -> dict[str, Any]:
    state = require_initialized()
    daemon = protocol.status()
    return {
        "product": PRODUCT_NAME,
        "initialized_at": state["initialized_at"],
        "device": state["device"],
        "daemon": daemon,
        "session_expires_at": session["expires_at"],
    }


@app.get("/api/service")
def get_service(
    _: dict[str, Any] = Depends(require_roles("system_admin")),
) -> dict[str, Any]:
    return service_snapshot()


def control_service(
    action: str,
    payload: ServiceControlRequest,
    request: Request,
    session: dict[str, Any],
) -> dict[str, Any]:
    expected = {
        "start": "START SERVICE",
        "stop": "STOP SERVICE",
        "restart": "RESTART SERVICE",
    }
    if action not in expected:
        raise HTTPException(404, "服务操作不存在")
    if not hmac.compare_digest(payload.confirmation, expected[action]):
        raise HTTPException(403, f"确认文字不正确，应输入 {expected[action]}")

    with service_control_lock:
        before = service_snapshot(include_daemon=False)
        try:
            if action == "start":
                if before["running"]:
                    raise HTTPException(409, "密码服务已经在运行")
                service_supervisor.start()
            elif action == "stop":
                if not before["running"]:
                    raise HTTPException(409, "密码服务当前未运行")
                service_supervisor.stop()
            else:
                if before["running"]:
                    service_supervisor.stop()
                service_supervisor.start()
            after = service_snapshot(include_daemon=action != "stop")
        except Exception as error:
            audit(
                request, session["username"], f"service_{action}", "sdfxd", "failure",
                level="ERROR", category="service", details=str(error),
            )
            raise

    audit(
        request, session["username"], f"service_{action}", "sdfxd", "success",
        category="service",
        details=f"state={before['supervisor_state']}->{after['supervisor_state']}",
    )
    return after


@app.post("/api/service/{action}")
def update_service(
    action: str,
    payload: ServiceControlRequest,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("system_admin", csrf=True)),
) -> dict[str, Any]:
    return control_service(action, payload, request, session)


@app.get("/api/administrators")
def list_administrators(
    _: dict[str, Any] = Depends(require_roles("super_admin")),
) -> list[dict[str, Any]]:
    state = require_initialized()
    return [
        {
            "username": username,
            "role": user["role"],
            "role_label": ROLE_LABELS[user["role"]],
            "enabled": user.get("enabled", True),
            "login_mode": user_login_mode(user),
            "login_mode_label": LOGIN_MODE_LABELS[user_login_mode(user)],
            "created_at": user.get("created_at", state["initialized_at"]),
            "ukey_auth": public_ukey_binding(user),
        }
        for username, user in sorted(state.get("users", {}).items())
    ]


@app.post("/api/administrators", status_code=201)
def create_administrator(
    payload: UserCreateRequest,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("super_admin", csrf=True)),
) -> dict[str, Any]:
    if not USERNAME_RE.fullmatch(payload.username):
        raise HTTPException(422, "用户名仅允许 3–32 位字母、数字、点、横线和下划线")
    if payload.role not in ROLES:
        raise HTTPException(422, "管理员角色无效")
    state = require_initialized()
    if payload.username in state.get("users", {}):
        raise HTTPException(409, "管理员已经存在")
    stored_password = password_record(payload.password, payload.username, session["username"])
    state.setdefault("users", {})[payload.username] = {
        "role": payload.role,
        "enabled": True,
        "login_mode": "password",
        "password": stored_password,
        "created_at": int(time.time()),
    }
    atomic_json_write(STATE_FILE, state)
    audit(request, session["username"], "administrator_create", payload.username, "success", category="access", details=f"role={payload.role}")
    return {
        "username": payload.username,
        "role": payload.role,
        "role_label": ROLE_LABELS[payload.role],
        "enabled": True,
        "login_mode": "password",
        "login_mode_label": LOGIN_MODE_LABELS["password"],
    }


@app.post("/api/administrators/{username}/password-salt")
def create_administrator_password_salt(
    username: str,
    session: dict[str, Any] = Depends(require_roles("super_admin", csrf=True)),
) -> dict[str, str | int]:
    if not USERNAME_RE.fullmatch(username):
        raise HTTPException(422, "用户名仅允许 3–32 位字母、数字、点、横线和下划线")
    return issue_password_salt(
        username, session["username"], preserve_existing=True
    )


@app.patch("/api/administrators/{username}")
def update_administrator(
    username: str,
    payload: UserUpdateRequest,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("super_admin", csrf=True)),
) -> dict[str, Any]:
    state = require_initialized()
    user = state.get("users", {}).get(username)
    if not isinstance(user, dict):
        raise HTTPException(404, "管理员不存在")
    if payload.role is not None:
        if payload.role not in ROLES:
            raise HTTPException(422, "管理员角色无效")
        user["role"] = payload.role
    if payload.password is not None:
        user["password"] = password_record(
            payload.password, username, session["username"]
        )
    if payload.enabled is not None:
        if username == session["username"] and not payload.enabled:
            raise HTTPException(409, "不能停用当前登录账户")
        user["enabled"] = payload.enabled
    if payload.login_mode is not None:
        if payload.login_mode not in LOGIN_MODES:
            raise HTTPException(422, "管理员登录方式无效")
        if payload.login_mode == "password_ukey":
            binding = user.get("ukey_auth")
            if not isinstance(binding, dict) or not binding.get("enabled", False):
                raise HTTPException(409, "请先配置并启用该管理员的 UKey，再选择此登录方式")
        user["login_mode"] = payload.login_mode
    enabled_super = sum(
        1 for item in state["users"].values()
        if item.get("role") == "super_admin" and item.get("enabled", True)
    )
    if enabled_super == 0:
        raise HTTPException(409, "至少保留一个启用的超级管理员")
    atomic_json_write(STATE_FILE, state)
    if not user.get("enabled", True):
        with db() as connection:
            connection.execute("DELETE FROM sessions WHERE username = ?", (username,))
    audit(
        request, session["username"], "administrator_update", username,
        "success", category="access",
        details=(
            f"role={user['role']};enabled={user.get('enabled', True)};"
            f"login_mode={user_login_mode(user)}"
        ),
    )
    return {
        "username": username,
        "role": user["role"],
        "role_label": ROLE_LABELS[user["role"]],
        "enabled": user.get("enabled", True),
        "login_mode": user_login_mode(user),
        "login_mode_label": LOGIN_MODE_LABELS[user_login_mode(user)],
    }


@app.put("/api/administrators/{username}/ukey")
def configure_administrator_ukey(
    username: str,
    payload: UKeyBindingRequest,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("super_admin", csrf=True)),
) -> dict[str, Any]:
    state = require_initialized()
    user = state.get("users", {}).get(username)
    if not isinstance(user, dict):
        raise HTTPException(404, "管理员不存在")
    user_der, ca_der, validation = validate_ukey_binding(
        payload.user_certificate_base64,
        payload.ca_certificate_base64,
    )
    if not payload.enabled and user_login_mode(user) == "password_ukey":
        raise HTTPException(409, "请先把管理员登录方式改为“用户名口令”，再停用 UKey")
    configured_at = int(time.time())
    with state_lock:
        refreshed_state = require_initialized()
        refreshed_user = refreshed_state.get("users", {}).get(username)
        if not isinstance(refreshed_user, dict):
            raise HTTPException(404, "管理员不存在")
        refreshed_user["ukey_auth"] = {
            "enabled": payload.enabled,
            "user_certificate_base64": base64.b64encode(user_der).decode("ascii"),
            "ca_certificate_base64": base64.b64encode(ca_der).decode("ascii"),
            "revocation_mode": "off",
            "trust_mode": "uploaded_ca_anchor",
            "configured_at": configured_at,
            "configured_by": session["username"],
            "validation": validation,
        }
        atomic_json_write(STATE_FILE, refreshed_state)
        result = public_ukey_binding(refreshed_user)
    audit(
        request, session["username"], "administrator_ukey_configure", username,
        "success", category="access",
        details=(
            f"enabled={payload.enabled};"
            f"certificate_sha256={validation['user_certificate']['sha256_fingerprint']}"
        ),
    )
    return result or {}


@app.delete("/api/administrators/{username}/ukey")
def remove_administrator_ukey(
    username: str,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("super_admin", csrf=True)),
) -> dict[str, bool]:
    with state_lock:
        state = require_initialized()
        user = state.get("users", {}).get(username)
        if not isinstance(user, dict):
            raise HTTPException(404, "管理员不存在")
        if not isinstance(user.get("ukey_auth"), dict):
            raise HTTPException(404, "管理员尚未配置 UKey 身份鉴别")
        if user_login_mode(user) == "password_ukey":
            raise HTTPException(409, "请先把管理员登录方式改为“用户名口令”，再移除 UKey 配置")
        del user["ukey_auth"]
        atomic_json_write(STATE_FILE, state)
    with db() as connection:
        connection.execute("DELETE FROM ukey_challenges WHERE username = ?", (username,))
    audit(
        request, session["username"], "administrator_ukey_remove", username,
        "success", category="access",
    )
    return {"removed": True}


@app.delete("/api/administrators/{username}")
def delete_administrator(
    username: str,
    payload: ConfirmRequest,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("super_admin", csrf=True)),
) -> dict[str, bool]:
    if username == session["username"]:
        raise HTTPException(409, "不能删除当前登录账户")
    if payload.confirmation != "DELETE" or not verify_session_password(payload.password, session):
        raise HTTPException(403, "确认文字或管理员密码不正确")
    state = require_initialized()
    user = state.get("users", {}).get(username)
    if not isinstance(user, dict):
        raise HTTPException(404, "管理员不存在")
    if user.get("role") == "super_admin":
        remaining = sum(
            1 for name, item in state["users"].items()
            if name != username and item.get("role") == "super_admin" and item.get("enabled", True)
        )
        if remaining == 0:
            raise HTTPException(409, "至少保留一个启用的超级管理员")
    del state["users"][username]
    atomic_json_write(STATE_FILE, state)
    with db() as connection:
        connection.execute("DELETE FROM sessions WHERE username = ?", (username,))
    audit(request, session["username"], "administrator_delete", username, "success", category="access")
    return {"deleted": True}

@app.get("/api/device")
def get_device(_: dict[str, Any] = Depends(require_roles("system_admin"))) -> dict[str, Any]:
    return require_initialized()["device"]


@app.patch("/api/device")
def update_device(
    payload: DeviceUpdate,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("system_admin", csrf=True)),
) -> dict[str, Any]:
    validate_metadata(payload.vendor, payload.device_name, payload.serial)
    state = require_initialized()
    protocol.configure_device(payload.vendor.strip(), payload.device_name.strip(), payload.serial.strip())
    state["device"] = {
        "vendor": payload.vendor.strip(),
        "device_name": payload.device_name.strip(),
        "serial": payload.serial.strip(),
    }
    atomic_json_write(STATE_FILE, state)
    audit(request, session["username"], "update", "device", "success")
    return state["device"]


@app.get("/api/keys")
def list_keys(_: dict[str, Any] = Depends(require_roles("security_admin"))) -> list[dict[str, Any]]:
    return attach_key_lifecycle(protocol.keys())


@app.get("/api/keks")
def list_keks(_: dict[str, Any] = Depends(require_roles("security_admin"))) -> list[dict[str, Any]]:
    return attach_key_lifecycle(protocol.keks(), "kek")


@app.post("/api/keks", status_code=201)
def create_kek(
    payload: KekCreateRequest,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("security_admin", csrf=True)),
) -> dict[str, Any]:
    if not 1 <= payload.index <= 1024:
        raise HTTPException(422, "对称密钥索引必须为 1–1024")
    validate_validity_days(payload.validity_days)
    protocol.admin(CMD_ADMIN_KEK_CREATE, (payload.index, 0, 0, 0))
    save_key_lifecycle("SM4", "kek", payload.index, payload.validity_days)
    audit(request, session["username"], "create", f"kek:{payload.index}", "success",
          details=f"validity_days={payload.validity_days}")
    return next(item for item in attach_key_lifecycle(protocol.keks(), "kek") if item["index"] == payload.index)


@app.delete("/api/keks/{index}")
def delete_kek(
    index: int,
    payload: ConfirmRequest,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("security_admin", csrf=True)),
) -> dict[str, bool]:
    state = require_initialized()
    if not 1 <= index <= 1024:
        raise HTTPException(422, "对称密钥索引必须为 1–1024")
    if payload.confirmation != "DELETE" or not verify_session_password(payload.password, session):
        raise HTTPException(403, "确认文字或管理员密码不正确")
    protocol.admin(CMD_ADMIN_KEK_DELETE, (index, 0, 0, 0))
    delete_key_lifecycle("SM4", "kek", index)
    audit(request, session["username"], "delete", f"kek:{index}", "success")
    return {"deleted": True}


@app.put("/api/keks/{index}/validity")
def update_kek_validity(
    index: int, payload: KeyValidityRequest, request: Request,
    session: dict[str, Any] = Depends(require_roles("security_admin", csrf=True)),
) -> dict[str, Any]:
    if not 1 <= index <= 1024:
        raise HTTPException(422, "对称密钥索引必须为 1–1024")
    item = next((item for item in protocol.keks() if item["index"] == index), None)
    if item is None:
        raise HTTPException(404, "对称密钥不存在")
    save_key_lifecycle("SM4", "kek", index, payload.validity_days,
                       created_at=int(item.get("created_at") or time.time()))
    audit(request, session["username"], "update_validity", f"kek:{index}", "success",
          category="key", details=f"validity_days={payload.validity_days}")
    return next(item for item in attach_key_lifecycle(protocol.keks(), "kek") if item["index"] == index)


@app.post("/api/keks/{index}/enable")
def enable_kek(
    index: int,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("security_admin", csrf=True)),
) -> dict[str, bool]:
    if not 1 <= index <= 1024:
        raise HTTPException(422, "对称密钥索引必须为 1–1024")
    protocol.admin(CMD_ADMIN_KEK_ENABLE, (index, 0, 0, 0))
    audit(request, session["username"], "enable", f"kek:{index}", "success")
    return {"enabled": True}


@app.post("/api/keks/{index}/disable")
def disable_kek(
    index: int,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("security_admin", csrf=True)),
) -> dict[str, bool]:
    if not 1 <= index <= 1024:
        raise HTTPException(422, "对称密钥索引必须为 1–1024")
    protocol.admin(CMD_ADMIN_KEK_DISABLE, (index, 0, 0, 0))
    audit(request, session["username"], "disable", f"kek:{index}", "success")
    return {"enabled": False}

@app.post("/api/keks/{index}/verify")
def verify_kek_integrity(
    index: int,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("security_admin", csrf=True)),
) -> dict[str, Any]:
    if not 1 <= index <= 1024:
        raise HTTPException(422, "对称密钥索引必须为 1–1024")
    try:
        result = json.loads(protocol.admin(CMD_ADMIN_KEK_VERIFY, (index, 0, 0, 0)))
    except DaemonError as error:
        if error.status != SDR_KEYERR:
            raise
        result = {
            "type": "kek", "index": index, "algorithm": "HMAC-SM3",
            "key_algorithm": "SM4", "valid": False,
        }
    audit(
        request, session["username"], "integrity_verify", f"kek:{index}",
        "success" if result.get("valid") else "failure", category="key",
        level="INFO" if result.get("valid") else "ERROR",
    )
    return result


@app.post("/api/keys", status_code=201)
def create_key(
    payload: KeyCreateRequest,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("security_admin", csrf=True)),
) -> dict[str, Any]:
    params = list(key_params(payload.type, payload.index))
    algorithm = key_algorithm(payload.algorithm)
    encoded = payload.password.encode()
    if len(encoded) != 0 and not 8 <= len(encoded) <= 256:
        raise HTTPException(422, "密钥口令必须为空或 8–256 字节")
    validate_validity_days(payload.validity_days)
    if algorithm == "RSA":
        bits = 2048 if payload.bits is None else payload.bits
        if bits < 1024 or bits > 2048 or bits % 256:
            raise HTTPException(422, "RSA 密钥长度必须为 1024–2048 且是 256 的倍数")
        params[2] = bits
        command = CMD_ADMIN_RSA_KEY_CREATE
    else:
        if payload.bits not in (None, 256):
            raise HTTPException(422, "SM2 密钥长度必须为 256")
        command = CMD_ADMIN_KEY_CREATE
    protocol.admin(command, tuple(params), encoded)
    save_key_lifecycle(algorithm, payload.type, payload.index, payload.validity_days)
    target = f"{algorithm.lower()}:{payload.type}:{payload.index}"
    audit(request, session["username"], "create", target, "success", category="key",
          details=f"validity_days={payload.validity_days}")
    return next(item for item in attach_key_lifecycle(protocol.keys()) if item["algorithm"] == algorithm and item["type"] == payload.type and item["index"] == payload.index)


@app.delete("/api/keys/{key_type}/{index}")
def delete_key(
    key_type: str, index: int, payload: ConfirmRequest, request: Request,
    algorithm: str = "SM2",
    session: dict[str, Any] = Depends(require_roles("security_admin", csrf=True)),
) -> dict[str, bool]:
    if payload.confirmation != "DELETE" or not verify_session_password(payload.password, session):
        raise HTTPException(403, "确认文字或管理员密码不正确")
    algorithm = key_algorithm(algorithm)
    command = key_admin_command(algorithm, CMD_ADMIN_KEY_DELETE, CMD_ADMIN_RSA_KEY_DELETE)
    protocol.admin(command, key_params(key_type, index))
    delete_key_lifecycle(algorithm, key_type, index)
    audit(request, session["username"], "delete", f"{algorithm.lower()}:{key_type}:{index}", "success", category="key")
    return {"deleted": True}


@app.put("/api/keys/{key_type}/{index}/validity")
def update_key_validity(
    key_type: str, index: int, payload: KeyValidityRequest, request: Request,
    algorithm: str = "SM2",
    session: dict[str, Any] = Depends(require_roles("security_admin", csrf=True)),
) -> dict[str, Any]:
    algorithm = key_algorithm(algorithm)
    key_params(key_type, index)
    item = next((item for item in protocol.keys()
                 if item["algorithm"] == algorithm and item["type"] == key_type
                 and item["index"] == index), None)
    if item is None:
        raise HTTPException(404, "内部密钥不存在")
    save_key_lifecycle(algorithm, key_type, index, payload.validity_days,
                       created_at=int(item.get("created_at") or time.time()))
    audit(request, session["username"], "update_validity",
          f"{algorithm.lower()}:{key_type}:{index}", "success", category="key",
          details=f"validity_days={payload.validity_days}")
    return next(item for item in attach_key_lifecycle(protocol.keys())
                if item["algorithm"] == algorithm and item["type"] == key_type
                and item["index"] == index)


@app.post("/api/keys/{key_type}/{index}/enable")
def enable_key(key_type: str, index: int, request: Request, algorithm: str = "SM2",
    session: dict[str, Any] = Depends(require_roles("security_admin", csrf=True))) -> dict[str, bool]:
    algorithm = key_algorithm(algorithm)
    protocol.admin(key_admin_command(algorithm, CMD_ADMIN_KEY_ENABLE, CMD_ADMIN_RSA_KEY_ENABLE), key_params(key_type, index))
    audit(request, session["username"], "enable", f"{algorithm.lower()}:{key_type}:{index}", "success", category="key")
    return {"enabled": True}


@app.post("/api/keys/{key_type}/{index}/disable")
def disable_key(key_type: str, index: int, request: Request, algorithm: str = "SM2",
    session: dict[str, Any] = Depends(require_roles("security_admin", csrf=True))) -> dict[str, bool]:
    algorithm = key_algorithm(algorithm)
    protocol.admin(key_admin_command(algorithm, CMD_ADMIN_KEY_DISABLE, CMD_ADMIN_RSA_KEY_DISABLE), key_params(key_type, index))
    audit(request, session["username"], "disable", f"{algorithm.lower()}:{key_type}:{index}", "success", category="key")
    return {"enabled": False}


@app.get("/api/keys/{key_type}/{index}/public")
def export_public_key(key_type: str, index: int, algorithm: str = "SM2",
    _: dict[str, Any] = Depends(require_roles("security_admin"))) -> dict[str, Any]:
    algorithm = key_algorithm(algorithm)
    raw = protocol.admin(key_admin_command(algorithm, CMD_ADMIN_KEY_PUBLIC, CMD_ADMIN_RSA_KEY_PUBLIC), key_params(key_type, index))
    return {"type": key_type, "index": index, "algorithm": algorithm,
        "format": "GMT-0018-RSArefPublicKey" if algorithm == "RSA" else "GMT-0018-ECCrefPublicKey",
        "data": base64.b64encode(raw).decode()}


@app.post("/api/keys/{key_type}/{index}/password")
def change_key_password(key_type: str, index: int, payload: KeyPasswordRequest,
    request: Request, algorithm: str = "SM2",
    session: dict[str, Any] = Depends(require_roles("security_admin", csrf=True))) -> dict[str, bool]:
    old, new = payload.old_password.encode(), payload.new_password.encode()
    if (len(old) and not 8 <= len(old) <= 256) or (len(new) and not 8 <= len(new) <= 256):
        raise HTTPException(422, "密钥口令必须为空或 8–256 字节")
    algorithm = key_algorithm(algorithm)
    params = list(key_params(key_type, index)); params[2], params[3] = len(old), len(new)
    protocol.admin(key_admin_command(algorithm, CMD_ADMIN_KEY_PASSWORD, CMD_ADMIN_RSA_KEY_PASSWORD), tuple(params), old + new)
    audit(request, session["username"], "change_password", f"{algorithm.lower()}:{key_type}:{index}", "success", category="key")
    return {"changed": True}


@app.post("/api/keys/{key_type}/{index}/verify")
def verify_key_integrity(key_type: str, index: int, request: Request,
    algorithm: str = "SM2",
    session: dict[str, Any] = Depends(require_roles("security_admin", csrf=True))) -> dict[str, Any]:
    algorithm = key_algorithm(algorithm)
    target = f"{algorithm.lower()}:{key_type}:{index}"
    try:
        raw = protocol.admin(
            key_admin_command(algorithm, CMD_ADMIN_KEY_VERIFY, CMD_ADMIN_RSA_KEY_VERIFY),
            key_params(key_type, index),
        )
        result = json.loads(raw)
    except DaemonError as error:
        if error.status != SDR_KEYERR:
            raise
        result = {"type": key_type, "index": index, "algorithm": "HMAC-SM3",
                  "key_algorithm": algorithm, "valid": False}
    audit(request, session["username"], "integrity_verify", target,
        "success" if result.get("valid") else "failure", category="key",
        level="INFO" if result.get("valid") else "ERROR")
    return result


@app.post("/api/keys/{key_type}/{index}/reindex")
def reindex_key(key_type: str, index: int, payload: KeyReindexRequest,
    request: Request, algorithm: str = "SM2",
    session: dict[str, Any] = Depends(require_roles("security_admin", csrf=True))) -> dict[str, Any]:
    old_params = key_params(key_type, index); key_params(key_type, payload.new_index)
    algorithm = key_algorithm(algorithm)
    command = key_admin_command(algorithm, CMD_ADMIN_KEY_REINDEX, CMD_ADMIN_RSA_KEY_REINDEX)
    protocol.admin(command, (old_params[0], index, payload.new_index, 0))
    reindex_key_lifecycle(algorithm, key_type, index, payload.new_index)
    audit(request, session["username"], "reindex", f"{algorithm.lower()}:{key_type}:{index}",
        "success", category="key", details=f"new_index={payload.new_index}")
    return next(item for item in attach_key_lifecycle(protocol.keys()) if item["algorithm"] == algorithm and item["type"] == key_type and item["index"] == payload.new_index)
@app.get("/api/sessions")
def list_sessions(_: dict[str, Any] = Depends(require_roles("system_admin"))) -> list[dict[str, Any]]:
    return protocol.sessions()


@app.delete("/api/sessions/{session_id}")
def close_session(
    session_id: int,
    payload: ConfirmRequest,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("system_admin", csrf=True)),
) -> dict[str, bool]:
    state = require_initialized()
    if payload.confirmation != "TERMINATE" or not verify_session_password(payload.password, session):
        raise HTTPException(403, "确认文字或管理员密码不正确")
    if session_id <= 0:
        raise HTTPException(422, "会话编号无效")
    protocol.admin(CMD_ADMIN_SESSION_CLOSE, (session_id, 0, 0, 0))
    audit(request, session["username"], "terminate", f"session:{session_id}", "success")
    return {"closed": True}


@app.post("/api/crypto/selftest")
def crypto_selftest(
    request: Request,
    session: dict[str, Any] = Depends(require_roles("security_admin", csrf=True)),
) -> dict[str, Any]:
    started = time.perf_counter()
    result = protocol.selftest()
    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
    audit(request, session["username"], "self_test", "random-sm3-sm4-sm2-rsa", "success")
    return result


@app.post("/api/crypto/random")
def random_test(
    request: Request,
    length: int = 32,
    session: dict[str, Any] = Depends(require_roles("security_admin", csrf=True)),
) -> dict[str, Any]:
    if length < 1 or length > 1024:
        raise HTTPException(422, "随机数长度必须为 1–1024 字节")
    started = time.perf_counter()
    value = protocol.random(length)
    elapsed = round((time.perf_counter() - started) * 1000, 3)
    audit(request, session["username"], "self_test", "random", "success")
    return {"length": length, "hex": value.hex(), "elapsed_ms": elapsed}


@app.get("/api/audit/settings")
def get_audit_settings(
    _: dict[str, Any] = Depends(require_roles("audit_admin")),
) -> dict[str, Any]:
    return read_audit_settings()


@app.patch("/api/audit/settings")
def update_audit_settings(
    payload: AuditSettingsUpdate,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("audit_admin", csrf=True)),
) -> dict[str, Any]:
    level = payload.display_level.strip().upper()
    if payload.retention_days < 1 or payload.retention_days > 3650:
        raise HTTPException(422, "审计日志保留天数必须为 1–3650")
    if level not in AUDIT_LEVEL_ORDER:
        raise HTTPException(422, "显示级别必须为 DEBUG、INFO、WARN 或 ERROR")
    cutoff = int(time.time()) - payload.retention_days * 86400
    with db() as connection:
        connection.executemany(
            "INSERT OR REPLACE INTO manager_settings(key, value) VALUES (?, ?)",
            (("audit_retention_days", str(payload.retention_days)),
             ("audit_display_level", level)),
        )
        connection.execute("DELETE FROM audit WHERE occurred_at < ?", (cutoff,))
    audit(request, session["username"], "audit_settings_update", "audit", "success",
          category="audit", details=f"retention_days={payload.retention_days};display_level={level}")
    return {"retention_days": payload.retention_days, "display_level": level}


def split_filter_values(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def audit_filter_sql(
    *, start_at: int | None = None, end_at: int | None = None,
    minimum_level: str = "", levels: str = "", categories: str = "",
    results: str = "", username: str = "", action: str = "", target: str = "",
    remote_addr_filter: str = "", request_id: str = "", method: str = "",
    path: str = "", keyword: str = "",
) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if start_at is not None:
        clauses.append("occurred_at >= ?"); params.append(start_at)
    if end_at is not None:
        clauses.append("occurred_at <= ?"); params.append(end_at)
    selected_levels = [item.upper() for item in split_filter_values(levels)]
    if selected_levels:
        invalid = set(selected_levels) - set(AUDIT_LEVEL_ORDER)
        if invalid:
            raise HTTPException(422, "指定级别包含无效值")
        marks = ",".join("?" for _ in selected_levels)
        clauses.append(f"level IN ({marks})"); params.extend(selected_levels)
    else:
        normalized_minimum = minimum_level.strip().upper()
        if normalized_minimum:
            if normalized_minimum not in AUDIT_LEVEL_ORDER:
                raise HTTPException(422, "最低级别必须为 DEBUG、INFO、WARN 或 ERROR")
            clauses.append(
                "CASE level WHEN 'DEBUG' THEN 10 WHEN 'WARN' THEN 30 "
                "WHEN 'ERROR' THEN 40 ELSE 20 END >= ?"
            )
            params.append(AUDIT_LEVEL_ORDER[normalized_minimum])
    for column, raw in (("category", categories), ("result", results)):
        values = split_filter_values(raw)
        if values:
            marks = ",".join("?" for _ in values)
            clauses.append(f"{column} IN ({marks})"); params.extend(values)
    for column, value in (
        ("username", username), ("action", action), ("target", target),
        ("remote_addr", remote_addr_filter), ("request_id", request_id),
        ("method", method), ("path", path),
    ):
        if value.strip():
            clauses.append(f"{column} LIKE ?")
            params.append(f"%{value.strip()}%")
    if keyword.strip():
        fields = ("username", "action", "target", "remote_addr", "request_id", "path", "details")
        clauses.append("(" + " OR ".join(f"{field} LIKE ?" for field in fields) + ")")
        params.extend([f"%{keyword.strip()}%"] * len(fields))
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def query_audit_rows(*, limit: int, order: str, **filters: Any) -> list[dict[str, Any]]:
    where, params = audit_filter_sql(**filters)
    direction = "ASC" if order.lower() == "asc" else "DESC"
    with db() as connection:
        rows = connection.execute(
            f"""
            SELECT id, occurred_at, username, action, target, result, remote_addr,
                   level, category, request_id, method, path, details, user_agent
            FROM audit{where} ORDER BY id {direction} LIMIT ?
            """,
            (*params, limit),
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/audit/options")
def get_audit_options(
    _: dict[str, Any] = Depends(require_roles("audit_admin")),
) -> dict[str, Any]:
    with db() as connection:
        distinct = {
            column: [row[0] for row in connection.execute(
                f"SELECT DISTINCT {column} FROM audit WHERE {column} <> '' ORDER BY {column}"
            ).fetchall()]
            for column in ("category", "result", "username", "action", "method")
        }
    return {
        **distinct,
        "levels": list(AUDIT_LEVEL_ORDER),
        "formats": sorted(AUDIT_EXPORT_FORMATS),
        "fields": list(AUDIT_EXPORT_FIELDS),
    }


@app.get("/api/audit")
def get_audit(
    limit: int = 200, order: str = "desc", start_at: int | None = None,
    end_at: int | None = None, minimum_level: str = "", levels: str = "",
    categories: str = "", results: str = "", username: str = "",
    action: str = "", target: str = "", remote_addr: str = "",
    request_id: str = "", method: str = "", path: str = "", keyword: str = "",
    _: dict[str, Any] = Depends(require_roles("audit_admin")),
) -> list[dict[str, Any]]:
    if start_at is not None and end_at is not None and start_at > end_at:
        raise HTTPException(422, "开始时间不能晚于结束时间")
    if order.lower() not in {"asc", "desc"}:
        raise HTTPException(422, "排序方式必须为 asc 或 desc")
    if not levels.strip() and not minimum_level.strip():
        minimum_level = read_audit_settings()["display_level"]
    return query_audit_rows(
        limit=max(1, min(limit, 2000)), order=order, start_at=start_at, end_at=end_at,
        minimum_level=minimum_level, levels=levels, categories=categories,
        results=results, username=username, action=action, target=target,
        remote_addr_filter=remote_addr, request_id=request_id, method=method,
        path=path, keyword=keyword,
    )


@app.get("/api/audit/export")
def export_audit(
    format: str = "txt", fields: str = "", include_header: bool = True,
    limit: int = 100000, order: str = "asc", start_at: int | None = None,
    end_at: int | None = None, minimum_level: str = "", levels: str = "",
    categories: str = "", results: str = "", username: str = "",
    action: str = "", target: str = "", remote_addr: str = "",
    request_id: str = "", method: str = "", path: str = "", keyword: str = "",
    _: dict[str, Any] = Depends(require_roles("audit_admin")),
) -> Response:
    export_format = format.lower()
    if export_format not in AUDIT_EXPORT_FORMATS:
        raise HTTPException(422, "导出格式必须为 txt、csv 或 jsonl")
    if start_at is not None and end_at is not None and start_at > end_at:
        raise HTTPException(422, "开始时间不能晚于结束时间")
    if order.lower() not in {"asc", "desc"}:
        raise HTTPException(422, "排序方式必须为 asc 或 desc")
    if not levels.strip() and not minimum_level.strip():
        minimum_level = read_audit_settings()["display_level"]
    selected_fields = split_filter_values(fields) or list(AUDIT_EXPORT_FIELDS)
    if not selected_fields or set(selected_fields) - set(AUDIT_EXPORT_FIELDS):
        raise HTTPException(422, "导出字段包含无效值")
    rows = query_audit_rows(
        limit=max(1, min(limit, 100000)), order=order, start_at=start_at,
        end_at=end_at, minimum_level=minimum_level, levels=levels,
        categories=categories, results=results, username=username, action=action,
        target=target, remote_addr_filter=remote_addr, request_id=request_id,
        method=method, path=path, keyword=keyword,
    )
    documents: list[dict[str, Any]] = []
    for row in rows:
        item = {field: row.get(field, "") for field in selected_fields}
        if "occurred_at" in item:
            stamp = datetime.fromtimestamp(int(item["occurred_at"]), timezone.utc).astimezone()
            item["occurred_at"] = f"{stamp:%Y-%m-%d %H:%M:%S%z}"
        documents.append(item)

    if export_format == "csv":
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=selected_fields)
        if include_header:
            writer.writeheader()
        writer.writerows(documents)
        content = "\ufeff" + stream.getvalue()
        media_type = "text/csv; charset=utf-8"
    elif export_format == "jsonl":
        content = "\n".join(json.dumps(item, ensure_ascii=False) for item in documents)
        content += "\n" if content else ""
        media_type = "application/x-ndjson; charset=utf-8"
    else:
        lines: list[str] = []
        if include_header:
            lines.extend((
                f"# {PRODUCT_NAME} v{PRODUCT_VERSION} 审计日志",
                f"# exported_at={datetime.now().astimezone():%Y-%m-%d %H:%M:%S%z} records={len(documents)}",
                f"# fields={','.join(selected_fields)}",
            ))
        lines.extend("\t".join(f"{field}={item.get(field, '')}" for field in selected_fields) for item in documents)
        content = "\n".join(lines) + ("\n" if lines else "")
        media_type = "text/plain; charset=utf-8"
    filename = f"cryptokit-audit-{datetime.now():%Y%m%d-%H%M%S}.{export_format}"
    return Response(
        content, media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@app.get("/api/backups")
def list_backups(_: dict[str, Any] = Depends(require_roles("super_admin", "system_admin"))) -> list[dict[str, Any]]:
    return protocol.backups()


@app.post("/api/backups", status_code=201)
def create_backup(
    request: Request,
    session: dict[str, Any] = Depends(require_roles("super_admin", "system_admin", csrf=True)),
) -> dict[str, Any]:
    backup_id = secrets.token_hex(16)
    with maintenance_lock:
        maintenance_active.set()
        try:
            protocol.admin(CMD_ADMIN_BACKUP_CREATE, secret=backup_id.encode("ascii"))
        finally:
            maintenance_active.clear()
    audit(request, session["username"], "backup_create", f"backup:{backup_id}", "success")
    return next(item for item in protocol.backups() if item["id"] == backup_id)


@app.post("/api/backups/upload", status_code=201)
async def upload_backup(
    backup_id: str,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("super_admin", "system_admin", csrf=True)),
) -> dict[str, Any]:
    final_path = backup_path(backup_id)
    if final_path.exists():
        raise HTTPException(409, "同编号备份已经存在")
    temporary = BACKUP_ROOT / f".{backup_id}.{secrets.token_hex(8)}.upload"
    total = 0
    fd = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        with os.fdopen(fd, "wb", closefd=True) as stream:
            async for chunk in request.stream():
                total += len(chunk)
                if total > 256 * 1024 * 1024:
                    raise HTTPException(413, "备份文件不能超过 256 MiB")
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        if total < 1024:
            raise HTTPException(422, "备份文件过小或格式无效")
        os.replace(temporary, final_path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    audit(request, session["username"], "backup_upload", f"backup:{backup_id}", "success")
    return {"id": backup_id, "size": total}


@app.get("/api/backups/{backup_id}/download")
def download_backup(
    backup_id: str,
    _: dict[str, Any] = Depends(require_roles("super_admin", "system_admin")),
) -> FileResponse:
    path = backup_path(backup_id)
    if not path.is_file():
        raise HTTPException(404, "备份不存在")
    return FileResponse(
        path, media_type="application/octet-stream",
        filename=f"cryptokit-{backup_id}.sdfxbak",
    )


@app.delete("/api/backups/{backup_id}")
def delete_backup(
    backup_id: str,
    payload: ConfirmRequest,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("super_admin", "system_admin", csrf=True)),
) -> dict[str, bool]:
    state = require_initialized()
    backup_path(backup_id)
    if payload.confirmation != "DELETE" or not verify_session_password(payload.password, session):
        raise HTTPException(403, "确认文字或管理员密码不正确")
    protocol.admin(CMD_ADMIN_BACKUP_DELETE, secret=backup_id.encode("ascii"))
    audit(request, session["username"], "backup_delete", f"backup:{backup_id}", "success")
    return {"deleted": True}


@app.post("/api/backups/restore")
def restore_backup(
    payload: BackupRestoreRequest,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("super_admin", "system_admin", csrf=True)),
) -> dict[str, bool]:
    state = require_initialized()
    backup_path(payload.backup_id)
    if payload.confirmation != "RESTORE" or not verify_session_password(payload.password, session):
        raise HTTPException(403, "确认文字或管理员密码不正确")
    with maintenance_lock:
        maintenance_active.set()
        try:
            protocol.admin(
                CMD_ADMIN_BACKUP_RESTORE, secret=payload.backup_id.encode("ascii")
            )
        finally:
            maintenance_active.clear()
    initialize_storage()
    with db() as connection:
        connection.execute("DELETE FROM sessions")
    audit(request, session["username"], "backup_restore", f"backup:{payload.backup_id}", "success")
    return {"restored": True, "requires_login": True}


@app.post("/api/device/reset")
def reset_device(
    payload: ResetRequest,
    request: Request,
    response: Response,
    session: dict[str, Any] = Depends(require_roles("super_admin", "system_admin", csrf=True)),
) -> dict[str, bool]:
    state = require_initialized()
    serial_matches = hmac.compare_digest(payload.serial, state["device"]["serial"])
    password_matches = verify_session_password(payload.password, session)
    if payload.confirmation != "RESET DEVICE" or not serial_matches or not password_matches:
        raise HTTPException(403, "管理员密码、设备序列号或确认文字不正确")
    audit(request, session["username"], "device_reset", "device", "confirmed")
    with maintenance_lock:
        maintenance_active.set()
        try:
            protocol.admin(CMD_ADMIN_DEVICE_RESET)
        finally:
            maintenance_active.clear()
    with login_lock:
        login_failures.clear()
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"reset": True, "requires_initialization": True}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_ROOT / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_ROOT), name="static")
