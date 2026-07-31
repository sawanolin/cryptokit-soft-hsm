from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sqlite3
import struct
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel


PRODUCT_NAME = "CryptoKit SoftHSM Manager"
DATA_ROOT = Path(os.getenv("SDFX_DATA_DIR", "/var/lib/sdfx")).resolve()
WEB_ROOT = DATA_ROOT / "web"
STATE_FILE = WEB_ROOT / "state.json"
DATABASE_FILE = WEB_ROOT / "manager.db"
BACKUP_ROOT = DATA_ROOT / "backups"
TOKEN_FILE = Path(os.getenv("SDFX_ADMIN_TOKEN_FILE", "/run/sdfx/admin.token"))
STATIC_ROOT = Path(__file__).resolve().parent.parent / "static"
SESSION_TTL = int(os.getenv("SDFX_WEB_SESSION_TTL", "1800"))
COOKIE_SECURE = os.getenv("SDFX_WEB_SECURE_COOKIE", "false").lower() == "true"
COOKIE_NAME = "sdfx_manager_session"

MAGIC = 0x53444658
VERSION = 0x00020000
SDR_OK = 0
SDR_KEYERR = 0x01000015
CMD_OPEN_DEVICE = 0x0001
CMD_CLOSE_DEVICE = 0x0002
CMD_OPEN_SESSION = 0x0003
CMD_CLOSE_SESSION = 0x0004
CMD_GENERATE_RANDOM = 0x0006
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
ROLE_LABELS = {
    "super_admin": "超级管理员",
    "system_admin": "系统管理员",
    "security_admin": "安全管理员",
    "audit_admin": "审计管理员",
}
ROLE_PAGES = {
    "super_admin": ["administrators", "maintenance"],
    "system_admin": ["dashboard", "device", "sessions", "maintenance"],
    "security_admin": ["keys", "testing"],
    "audit_admin": ["audit"],
}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
BACKUP_ID_RE = re.compile(r"^[0-9a-f]{32}$")
login_lock = threading.Lock()
login_failures: dict[str, list[float]] = {}
maintenance_lock = threading.Lock()
maintenance_active = threading.Event()


class DaemonError(RuntimeError):
    def __init__(self, status: int, message: str = "密码服务调用失败") -> None:
        self.status = status
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
            raise DaemonError(status)
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


protocol = ProtocolClient()


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
        return state
    except FileNotFoundError:
        return None


def password_record(password: str) -> dict[str, Any]:
    salt = secrets.token_bytes(16)
    rounds = 600_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, rounds)
    return {
        "algorithm": "pbkdf2-sha256",
        "rounds": rounds,
        "salt": base64.b64encode(salt).decode(),
        "digest": base64.b64encode(digest).decode(),
    }


def verify_password(password: str, record: dict[str, Any]) -> bool:
    try:
        salt = base64.b64decode(record["salt"], validate=True)
        expected = base64.b64decode(record["digest"], validate=True)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt, int(record["rounds"])
        )
        return hmac.compare_digest(actual, expected)
    except (KeyError, ValueError, TypeError):
        return False


def db() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_FILE, timeout=5)
    connection.row_factory = sqlite3.Row
    return connection


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
    os.chmod(DATABASE_FILE, 0o600)


initialize_storage()
app = FastAPI(title=PRODUCT_NAME, docs_url=None, redoc_url=None)


class InitializeRequest(BaseModel):
    username: str
    password: str
    vendor: str = "SDFX Project"
    device_name: str = "SDFX-1.0"
    serial: str = "SW000001"



class LoginRequest(BaseModel):
    username: str
    password: str


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


class KekCreateRequest(BaseModel):
    index: int


class KeyPasswordRequest(BaseModel):
    old_password: str = ""
    new_password: str = ""


class KeyReindexRequest(BaseModel):
    new_index: int


class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: str


class UserUpdateRequest(BaseModel):
    password: str | None = None
    role: str | None = None
    enabled: bool | None = None


class ConfirmRequest(BaseModel):
    password: str
    confirmation: str


class BackupRestoreRequest(BaseModel):
    backup_id: str
    password: str
    confirmation: str


class ResetRequest(BaseModel):
    password: str
    serial: str
    confirmation: str


class AuditSettingsUpdate(BaseModel):
    retention_days: int
    display_level: str


def validate_metadata(vendor: str, device_name: str, serial: str) -> None:
    values = ((vendor, 40, "厂商"), (device_name, 16, "设备名"), (serial, 16, "序列号"))
    for value, maximum, label in values:
        encoded = value.encode("utf-8")
        if not value.strip() or len(encoded) > maximum:
            raise HTTPException(422, f"{label}必须为 1–{maximum} 字节")


def validate_admin_password(password: str) -> None:
    if len(password) < 10 or len(password) > 128:
        raise HTTPException(422, "管理员密码长度必须为 10–128 个字符")
    classes = sum(
        bool(re.search(pattern, password))
        for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]")
    )
    if classes < 3:
        raise HTTPException(422, "管理员密码需包含大写、小写、数字、符号中的至少三类")


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


def verify_session_password(password: str, session: dict[str, Any]) -> bool:
    state = require_initialized()
    user = state.get("users", {}).get(session["username"], {})
    return isinstance(user, dict) and verify_password(password, user.get("password", {}))


def require_initialized() -> dict[str, Any]:
    state = load_state()
    if state is None:
        raise HTTPException(409, "设备尚未初始化")
    return state


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
        response = Response(
            json.dumps(
                {"error": {"code": "sdf_error", "message": str(error)}, "request_id": request_id},
                ensure_ascii=False,
            ),
            status_code=502,
            media_type="application/json",
        )
    except (ConnectionError, OSError, json.JSONDecodeError) as error:
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
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/health")
def health() -> dict[str, Any]:
    status = protocol.status()
    return {
        "status": "ok",
        "product": PRODUCT_NAME,
        "initialized": load_state() is not None,
        "daemon": status,
    }


@app.post("/api/initialize", status_code=201)
def initialize(payload: InitializeRequest, request: Request) -> dict[str, Any]:
    if load_state() is not None:
        raise HTTPException(409, "设备已经初始化")
    if not USERNAME_RE.fullmatch(payload.username):
        raise HTTPException(422, "用户名仅允许 3–32 位字母、数字、点、横线和下划线")
    validate_admin_password(payload.password)
    validate_metadata(payload.vendor, payload.device_name, payload.serial)

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
                "password": password_record(payload.password),
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
    valid = valid and verify_password(payload.password, user.get("password", {}))
    if not valid:
        with login_lock:
            login_failures.setdefault(address, []).append(now)
        audit(request, payload.username[:32], "login", "manager", "failure")
        raise HTTPException(401, "用户名或密码错误")

    with login_lock:
        login_failures.pop(address, None)
    csrf = create_session(response, payload.username)
    audit(request, payload.username, "login", "manager", "success")
    return {"username": payload.username, "role": user["role"], "role_label": ROLE_LABELS[user["role"]], "pages": ROLE_PAGES[user["role"]], "csrf": csrf, "expires_in": SESSION_TTL}


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
            "created_at": user.get("created_at", state["initialized_at"]),
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
    validate_admin_password(payload.password)
    state = require_initialized()
    if payload.username in state.get("users", {}):
        raise HTTPException(409, "管理员已经存在")
    state.setdefault("users", {})[payload.username] = {
        "role": payload.role,
        "enabled": True,
        "password": password_record(payload.password),
        "created_at": int(time.time()),
    }
    atomic_json_write(STATE_FILE, state)
    audit(request, session["username"], "administrator_create", payload.username, "success", category="access", details=f"role={payload.role}")
    return {"username": payload.username, "role": payload.role, "role_label": ROLE_LABELS[payload.role], "enabled": True}


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
        validate_admin_password(payload.password)
        user["password"] = password_record(payload.password)
    if payload.enabled is not None:
        if username == session["username"] and not payload.enabled:
            raise HTTPException(409, "不能停用当前登录账户")
        user["enabled"] = payload.enabled
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
    audit(request, session["username"], "administrator_update", username, "success", category="access", details=f"role={user['role']};enabled={user.get('enabled', True)}")
    return {"username": username, "role": user["role"], "role_label": ROLE_LABELS[user["role"]], "enabled": user.get("enabled", True)}


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
    return protocol.keys()


@app.get("/api/keks")
def list_keks(_: dict[str, Any] = Depends(require_roles("security_admin"))) -> list[dict[str, Any]]:
    return protocol.keks()


@app.post("/api/keks", status_code=201)
def create_kek(
    payload: KekCreateRequest,
    request: Request,
    session: dict[str, Any] = Depends(require_roles("security_admin", csrf=True)),
) -> dict[str, Any]:
    if not 1 <= payload.index <= 1024:
        raise HTTPException(422, "对称密钥索引必须为 1–1024")
    protocol.admin(CMD_ADMIN_KEK_CREATE, (payload.index, 0, 0, 0))
    audit(request, session["username"], "create", f"kek:{payload.index}", "success")
    return next(item for item in protocol.keks() if item["index"] == payload.index)


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
    audit(request, session["username"], "delete", f"kek:{index}", "success")
    return {"deleted": True}


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
    target = f"{algorithm.lower()}:{payload.type}:{payload.index}"
    audit(request, session["username"], "create", target, "success", category="key")
    return next(item for item in protocol.keys() if item["algorithm"] == algorithm and item["type"] == payload.type and item["index"] == payload.index)


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
    audit(request, session["username"], "delete", f"{algorithm.lower()}:{key_type}:{index}", "success", category="key")
    return {"deleted": True}


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
    audit(request, session["username"], "reindex", f"{algorithm.lower()}:{key_type}:{index}",
        "success", category="key", details=f"new_index={payload.new_index}")
    return next(item for item in protocol.keys() if item["algorithm"] == algorithm and item["type"] == key_type and item["index"] == payload.new_index)
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


@app.get("/api/audit")
def get_audit(
    limit: int = 100,
    _: dict[str, Any] = Depends(require_roles("audit_admin")),
) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 500))
    settings = read_audit_settings()
    threshold = AUDIT_LEVEL_ORDER[settings["display_level"]]
    with db() as connection:
        rows = connection.execute(
            """
            SELECT id, occurred_at, username, action, target, result, remote_addr,
                   level, category, request_id, method, path, details, user_agent
            FROM audit
            WHERE CASE level WHEN 'DEBUG' THEN 10 WHEN 'WARN' THEN 30
                  WHEN 'ERROR' THEN 40 ELSE 20 END >= ?
            ORDER BY id DESC LIMIT ?
            """,
            (threshold, limit),
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/audit/export")
def export_audit(
    _: dict[str, Any] = Depends(require_roles("audit_admin")),
) -> PlainTextResponse:
    settings = read_audit_settings()
    threshold = AUDIT_LEVEL_ORDER[settings["display_level"]]
    with db() as connection:
        rows = connection.execute(
            """
            SELECT occurred_at, username, action, target, result, remote_addr,
                   level, category, request_id, method, path, details
            FROM audit
            WHERE CASE level WHEN 'DEBUG' THEN 10 WHEN 'WARN' THEN 30
                  WHEN 'ERROR' THEN 40 ELSE 20 END >= ?
            ORDER BY id ASC
            """,
            (threshold,),
        ).fetchall()
    lines = []
    for row in rows:
        stamp = datetime.fromtimestamp(row["occurred_at"], timezone.utc).astimezone()
        line = (
            f"{stamp:%Y-%m-%d %H:%M:%S,%f} {row['level']} "
            f"[{row['category']}] [{row['username']}@{row['remote_addr']}] "
            f"[request:{row['request_id'] or '-'}] {row['method']} {row['path']} "
            f"action={row['action']} target={row['target']} result={row['result']}"
        )
        if row["details"]:
            line += f" details={row['details']}"
        lines.append(line)
    content = "\n".join(lines) + ("\n" if lines else "")
    filename = f"cryptokit-audit-{datetime.now():%Y%m%d-%H%M%S}.txt"
    return PlainTextResponse(
        content,
        media_type="text/plain; charset=utf-8",
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
