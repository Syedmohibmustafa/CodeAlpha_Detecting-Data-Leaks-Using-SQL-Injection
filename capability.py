import hashlib
import hmac
import time
from dataclasses import dataclass

from .config import get_settings


@dataclass
class CapabilityContext:
    username: str
    permission: str
    expires_at: int


def _sign_payload(payload: str) -> str:
    secret = get_settings().app_secret.encode("utf-8")
    signature = hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return signature


def generate_capability_code(username: str, permission: str = "read", ttl_seconds: int = 900) -> str:
    expires_at = int(time.time()) + ttl_seconds
    payload = f"{username}:{permission}:{expires_at}"
    signature = _sign_payload(payload)
    return f"{payload}:{signature}"


def verify_capability_code(capability_code: str, required_permission: str = "read") -> CapabilityContext:
    try:
        username, permission, expires_at_raw, provided_sig = capability_code.split(":", 3)
        expires_at = int(expires_at_raw)
    except (ValueError, TypeError) as exc:
        raise ValueError("Malformed capability code") from exc

    payload = f"{username}:{permission}:{expires_at}"
    expected_sig = _sign_payload(payload)

    if not hmac.compare_digest(provided_sig, expected_sig):
        raise ValueError("Invalid capability signature")
    if time.time() > expires_at:
        raise ValueError("Capability code expired")
    if permission != required_permission:
        raise ValueError("Capability permission mismatch")

    return CapabilityContext(username=username, permission=permission, expires_at=expires_at)
