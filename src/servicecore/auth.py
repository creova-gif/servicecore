from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import os
import threading
import time
from collections import deque
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

__all__ = [
    "CurrentTenant",
    "SlidingWindowRateLimiter",
    "TenantContext",
    "_resolve_auth_secret",
    "_verify_auth_token",
    "_verify_stripe_signature",
    "get_current_tenant",
    "mint_auth_token",
]

_DEV_FALLBACK_SECRET = "servicecore-dev-insecure-secret-do-not-use-in-prod"


class TenantContext(BaseModel):
    """Authenticated tenant identity extracted from a signed bearer token."""

    org_id: str = Field(min_length=1)
    sub: str = Field(min_length=1)


class SlidingWindowRateLimiter:
    """Thread-safe in-memory sliding-window rate limiter."""

    def __init__(self, max_requests: int, window_seconds: float = 60.0) -> None:
        if max_requests <= 0:
            raise ValueError("max_requests must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._lock = threading.Lock()
        self._events: dict[str, deque[float]] = {}

    def allow(self, key: str) -> tuple[bool, int]:
        """Record a request for key if under limit; return (allowed, retry_after_seconds)."""
        now = time.monotonic()
        cutoff = now - self._window_seconds
        with self._lock:
            bucket = self._events.setdefault(key, deque())
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self._max_requests:
                retry_after = max(1, math.ceil(self._window_seconds - (now - bucket[0])))
                return False, retry_after
            bucket.append(now)
            return True, 0


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode((segment + padding).encode("ascii"))


def mint_auth_token(
    org_id: str,
    sub: str,
    secret: str,
    *,
    ttl_seconds: int | None = 86400,
) -> str:
    """Mint an HMAC-SHA256 signed bearer token encoding org_id, sub, and optional exp/iat."""
    if not org_id.strip() or not sub.strip():
        raise ValueError("org_id and sub must be non-empty")
    if not secret:
        raise ValueError("secret must be non-empty")
    payload: dict[str, Any] = {"org_id": org_id, "sub": sub}
    if ttl_seconds is not None:
        now = int(time.time())
        payload["iat"] = now
        payload["exp"] = now + ttl_seconds
    payload_bytes = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    payload_b64 = _b64url_encode(payload_bytes)
    sig = hmac.new(secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest()
    return f"{payload_b64}.{_b64url_encode(sig)}"


def _resolve_auth_secret(configured_secret: str | None = None) -> str | None:
    if configured_secret:
        return configured_secret
    env_secret = os.environ.get("SERVICECORE_AUTH_SECRET")
    if env_secret:
        return env_secret
    if os.environ.get("SERVICECORE_DEV_MODE") == "1":
        return _DEV_FALLBACK_SECRET
    return None


def _verify_auth_token(token: str, secret: str) -> TenantContext:
    parts = token.split(".")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token format",
        )
    payload_b64, sig_b64 = parts
    try:
        provided_sig = _b64url_decode(sig_b64)
        expected_sig = hmac.new(
            secret.encode("utf-8"),
            payload_b64.encode("ascii"),
            hashlib.sha256,
        ).digest()
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed bearer token signature",
        ) from exc

    if not hmac.compare_digest(provided_sig, expected_sig):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token signature",
        )

    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        if not isinstance(payload, dict):
            raise TypeError("Token payload must be a JSON object")
        exp = payload.get("exp")
        if exp is not None and (isinstance(exp, bool) or not isinstance(exp, (int, float))):
            raise TypeError("Token exp claim must be numeric")
        tenant = TenantContext.model_validate(payload)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token payload",
        ) from exc

    if exp is not None and exp <= time.time():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        )
    return tenant


def get_current_tenant(
    request: Request,
    authorization: str | None = Header(default=None),
) -> TenantContext:
    """FastAPI dependency that authenticates the caller and returns TenantContext."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
        )
    token = authorization[len("Bearer ") :].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Empty bearer token",
        )

    configured = getattr(request.app.state, "auth_secret", None)
    secret = _resolve_auth_secret(configured if isinstance(configured, str) else None)
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication secret is not configured",
        )
    return _verify_auth_token(token, secret)


def _verify_stripe_signature(raw_body: bytes, sig_header: str | None, secret: str) -> bool:
    if not sig_header or not secret:
        return False

    timestamp: str | None = None
    v1_signatures: list[str] = []
    for item in sig_header.split(","):
        key, sep, value = item.strip().partition("=")
        if not sep:
            continue
        if key == "t":
            timestamp = value
        elif key == "v1":
            v1_signatures.append(value)

    if not timestamp or not v1_signatures:
        return False

    signed_payload = f"{timestamp}.".encode() + raw_body
    expected_sig = hmac.new(
        secret.encode("utf-8"),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    return any(hmac.compare_digest(expected_sig, candidate) for candidate in v1_signatures)


CurrentTenant = Annotated[TenantContext, Depends(get_current_tenant)]
