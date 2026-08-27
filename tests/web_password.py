"""Password-material helpers shared by Web end-to-end tests."""

from __future__ import annotations

import base64
import hashlib
from typing import Any


def password_hash(password: str, salt_base64: str) -> dict[str, str]:
    """Return the browser protocol value SM3(UTF8(password) || 8-byte salt)."""
    salt = base64.b64decode(salt_base64, validate=True)
    if len(salt) != 8:
        raise ValueError("account password salt must be exactly 8 bytes")
    digest = hashlib.new("sm3")
    digest.update(password.encode("utf-8"))
    digest.update(salt)
    return {"hash_base64": base64.b64encode(digest.digest()).decode("ascii")}


def password_material(password: str, salt_response: dict[str, Any]) -> dict[str, str]:
    """Build a create/change payload from a one-time SDF salt ticket."""
    result = password_hash(password, str(salt_response["salt_base64"]))
    result["ticket_id"] = str(salt_response["ticket_id"])
    return result
