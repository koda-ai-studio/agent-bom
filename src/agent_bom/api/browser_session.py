"""Signed browser session cookies for the dashboard.

The cookie deliberately stores an HMAC-signed session envelope, not the raw API
key that was used for the one-time exchange.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from agent_bom.api.api_key_record import OPERATOR_KEY_ID_PREFIX
from agent_bom.core.settings import env_bool

SESSION_COOKIE_NAME = "agent_bom_session"
SIGNED_OUT_COOKIE_NAME = "agent_bom_signed_out"
CSRF_COOKIE_NAME = "agent_bom_csrf"
CSRF_HEADER_NAME = "x-agent-bom-csrf"

_logger = logging.getLogger(__name__)
_EPHEMERAL_SIGNING_KEY = secrets.token_bytes(32)
_SIGNING_KEY_LOCK = threading.Lock()
# One configured-key fingerprint and derived key per process. Never retain
# tokens or authentication decisions; revocation and expiry remain live reads.
_SIGNING_KEY_CACHE: tuple[bytes, bytes] | None = None


class BrowserSessionError(Exception):
    """Raised when a browser session token is absent, invalid, or expired."""


def _env_flag(name: str) -> bool:
    return env_bool(name, False, on_invalid="default")


def _configured_api_replicas() -> int:
    raw = os.environ.get("AGENT_BOM_CONTROL_PLANE_REPLICAS", "").strip()
    if not raw:
        return 1
    try:
        return max(1, int(raw))
    except ValueError:
        _logger.warning("Invalid AGENT_BOM_CONTROL_PLANE_REPLICAS=%r; defaulting to 1", raw)
        return 1


def persistent_browser_session_signing_required() -> bool:
    """Clustered control planes need a stable key shared by every replica."""
    return _configured_api_replicas() > 1 or _env_flag("AGENT_BOM_REQUIRE_BROWSER_SESSION_SIGNING_KEY")


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _signing_key() -> bytes:
    global _SIGNING_KEY_CACHE

    from agent_bom.api.secret_source import resolve_secret

    # Resolve on every call so mounted-file rotation/removal takes effect.
    # Serialize cold derivations: concurrent untrusted cookies must not each
    # consume 600,000 PBKDF2 rounds for the same operator-controlled secret.
    with _SIGNING_KEY_LOCK:
        configured = resolve_secret("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY")
        if configured:
            raw = configured.encode("utf-8")
            fingerprint = hashlib.sha256(raw).digest()
            if _SIGNING_KEY_CACHE is None or not hmac.compare_digest(_SIGNING_KEY_CACHE[0], fingerprint):
                derived = hashlib.pbkdf2_hmac("sha256", raw, b"agent-bom-browser-session-signing-key:v1", 600_000, dklen=32)
                _SIGNING_KEY_CACHE = (fingerprint, derived)
            return _SIGNING_KEY_CACHE[1]
        _SIGNING_KEY_CACHE = None
    if persistent_browser_session_signing_required():
        raise BrowserSessionError("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY is required for clustered browser-session auth")
    _logger.warning(
        "AGENT_BOM_BROWSER_SESSION_SIGNING_KEY is not set; browser sessions use an ephemeral signing key "
        "and will be invalid after process restart"
    )
    return _EPHEMERAL_SIGNING_KEY


def create_browser_session_token(
    *,
    subject: str,
    role: str,
    tenant_id: str,
    auth_method: str,
    key_id: str | None = None,
    scopes: list[str] | None = None,
    static_api_key: str | None = None,
    operator_key_hash: str | None = None,
    max_age_seconds: int,
) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    csrf = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(16)
    payload: dict[str, Any] = {
        "v": 1,
        "sub": subject[:256],
        "role": role,
        "tenant_id": tenant_id,
        "auth_method": auth_method,
        "key_id": key_id,
        "scopes": scopes or [],
        "csrf_sha256": hashlib.sha256(f"{nonce}:{csrf}".encode("utf-8")).hexdigest(),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=max_age_seconds)).timestamp()),
        "nonce": nonce,
    }
    signing_key = _signing_key()
    if auth_method == "browser_session_static_api_key":
        if not static_api_key:
            raise BrowserSessionError("browser session requires its authenticated backing key")
        payload["static_key_binding"] = _static_key_binding(signing_key, nonce, static_api_key)
    if key_id and key_id.startswith(OPERATOR_KEY_ID_PREFIX):
        if not operator_key_hash:
            raise BrowserSessionError("browser session requires its authenticated operator key")
        payload["operator_key_binding"] = _operator_key_binding(signing_key, nonce, operator_key_hash)
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    encoded_payload = _b64encode(payload_bytes)
    signature = hmac.new(signing_key, encoded_payload.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded_payload}.{_b64encode(signature)}", csrf


def _static_key_binding(signing_key: bytes, nonce: str, raw_key: str) -> str:
    # Nonce-bound and keyed: the cookie exposes neither the credential nor an
    # offline password verifier. Bind the exact key authenticated at exchange.
    message = f"agent-bom-static-session:v1:{nonce}:{raw_key}".encode("utf-8")
    return hmac.new(signing_key, message, hashlib.sha256).hexdigest()


def _operator_key_binding(signing_key: bytes, nonce: str, key_hash: str) -> str:
    message = f"agent-bom-operator-session:v1:{nonce}:{key_hash}".encode("utf-8")
    return hmac.new(signing_key, message, hashlib.sha256).hexdigest()


def verify_operator_session_binding(binding: str, nonce: str, key_hash: str) -> bool:
    """Bind a stable operator slot to its current credential generation."""
    if not binding or not nonce:
        return False
    try:
        expected = _operator_key_binding(_signing_key(), nonce, key_hash)
    except (BrowserSessionError, OSError, ValueError):
        return False
    return hmac.compare_digest(binding.encode("utf-8"), expected.encode("ascii"))


def _verify_static_key_binding(payload: dict[str, Any], signing_key: bytes) -> None:
    from agent_bom.api.secret_source import resolve_secret
    from agent_bom.api.storage.deployment import clustered_control_plane_required

    try:
        current = resolve_secret("AGENT_BOM_API_KEY")
    except (OSError, ValueError) as exc:
        raise BrowserSessionError("browser session backing key is unavailable") from exc
    binding = str(payload.get("static_key_binding") or "")
    nonce = str(payload.get("nonce") or "")
    if not current or not binding or not nonce or clustered_control_plane_required():
        raise BrowserSessionError("browser session backing key is no longer active")
    expected = _static_key_binding(signing_key, nonce, current)
    if not hmac.compare_digest(binding.encode("utf-8"), expected.encode("ascii")):
        raise BrowserSessionError("browser session backing key is no longer active")


def _verified_session_payload(token: str) -> tuple[dict[str, Any], bytes]:
    """Authenticate the envelope without granting access or requiring a live login key."""
    if not token or "." not in token:
        raise BrowserSessionError("browser session cookie is missing or malformed")
    encoded_payload, encoded_signature = token.split(".", 1)
    try:
        payload_ascii = encoded_payload.encode("ascii")
        supplied = _b64decode(encoded_signature)
    except Exception as exc:  # noqa: BLE001
        raise BrowserSessionError("browser session signature is malformed") from exc
    if len(supplied) != hashlib.sha256().digest_size:
        raise BrowserSessionError("browser session signature is malformed")
    signing_key = _signing_key()
    expected = hmac.new(signing_key, payload_ascii, hashlib.sha256).digest()
    if not hmac.compare_digest(supplied, expected):
        raise BrowserSessionError("browser session signature is invalid")
    try:
        payload: dict[str, Any] = json.loads(_b64decode(encoded_payload).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise BrowserSessionError("browser session payload is invalid") from exc
    exp = int(payload.get("exp") or 0)
    if exp <= int(datetime.now(timezone.utc).timestamp()):
        raise BrowserSessionError("browser session is expired")
    return payload, signing_key


def verify_browser_session_token(token: str) -> dict[str, Any]:
    payload, signing_key = _verified_session_payload(token)
    if payload.get("auth_method") == "browser_session_static_api_key":
        _verify_static_key_binding(payload, signing_key)
    nonce = str(payload.get("nonce") or "")
    if nonce:
        from agent_bom.api.shared_auth_state import AuthStateUnavailable, get_auth_state

        try:
            if get_auth_state().is_nonce_revoked(nonce):
                raise BrowserSessionError("browser session has been revoked")
        except AuthStateUnavailable as exc:
            raise AuthStateUnavailable("Shared authentication state is unavailable") from exc
    return payload


def verify_csrf(payload: dict[str, Any], csrf_cookie: str, csrf_header: str) -> bool:
    if not csrf_cookie or not csrf_header or not csrf_cookie.isascii() or not csrf_header.isascii():
        return False
    if not hmac.compare_digest(csrf_cookie, csrf_header):
        return False
    expected = str(payload.get("csrf_sha256") or "")
    nonce = str(payload.get("nonce") or "")
    actual = hashlib.sha256(f"{nonce}:{csrf_cookie}".encode("utf-8")).hexdigest()
    return hmac.compare_digest(actual, expected)


def revoke_browser_session_token(token: str) -> bool:
    """Revoke a signed browser session nonce until its natural expiry."""
    try:
        # Logout must persist revocation even after the login key changed; a
        # later key rollback must not resurrect a cookie the user signed out of.
        payload, _ = _verified_session_payload(token)
    except BrowserSessionError:
        return False
    nonce = str(payload.get("nonce") or "")
    exp = int(payload.get("exp") or 0)
    if not nonce or exp <= int(datetime.now(timezone.utc).timestamp()):
        return False
    from agent_bom.api.shared_auth_state import get_auth_state

    backend = get_auth_state()
    if backend.is_nonce_revoked(nonce):
        return False
    backend.revoke_nonce(nonce, exp)
    backend.cleanup_expired()
    return True
