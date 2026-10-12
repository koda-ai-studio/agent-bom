"""Browser-session, SAML relay and auth rate-limit helpers for the enterprise auth routes."""

from __future__ import annotations

import base64
import binascii
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, Response

from agent_bom.api import host_guard as _host_guard
from agent_bom.api.dev_auth_state import get_dev_api_key, get_dev_api_role
from agent_bom.api.forwarded_identity import resolve_forwarded_client_ip, trusted_proxy_hops, trusted_proxy_networks
from agent_bom.core.settings import env_raw
from agent_bom.security import sanitize_error


def _auth_session_client_identity_posture() -> dict[str, Any]:
    """Describe whether forwarded client identity is safely active."""
    raw_hops = (env_raw("AGENT_BOM_TRUSTED_PROXY_HOPS") or "").strip()
    raw_cidrs = (env_raw("AGENT_BOM_TRUSTED_PROXY_CIDRS") or "").strip()
    hops = trusted_proxy_hops()
    networks = trusted_proxy_networks()
    active = bool(hops and networks)
    warning = None
    if raw_hops and not hops:
        warning = "trusted_proxy_hops_invalid"
    elif raw_cidrs and not networks:
        warning = "trusted_proxy_cidrs_invalid"
    elif bool(raw_hops) != bool(raw_cidrs):
        warning = "trusted_proxy_topology_incomplete"
    return {
        "source": "forwarded_chain" if active else "transport_peer",
        "forwarded_identity_active": active,
        "trusted_proxy_hops": hops,
        "trusted_proxy_network_count": len(networks),
        "warning": warning,
    }


def _client_fingerprint(request: Request) -> str:
    """Throttle identity for the API-key-exchange brute-force limiter.

    Defaults to the transport peer (``request.client.host``) so a hostile
    client cannot reset its brute-force window by spoofing a fresh
    ``X-Forwarded-For`` value on every attempt. The forwarded chain is only
    consulted only when the deployment declares both an explicit positive
    ``AGENT_BOM_TRUSTED_PROXY_HOPS`` count and transport-peer CIDRs in
    ``AGENT_BOM_TRUSTED_PROXY_CIDRS``. Trusted-proxy authentication proves
    identity-header attestation, not the forwarded-address topology. For a
    request received from an allowlisted proxy network, we take the
    Nth-from-rightmost entry and fall back to the transport peer when the chain
    is missing, malformed, oversized, or shorter than declared.
    """
    return resolve_forwarded_client_ip(
        peer_host=request.client.host if request.client else "",
        forwarded_for=request.headers.get("x-forwarded-for") or "",
        fallback="unknown",
    )[:128]


def _auth_session_limit() -> int:
    raw = (env_raw("AGENT_BOM_AUTH_SESSION_ATTEMPTS_PER_MINUTE") or "12").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 12


def _check_auth_session_rate_limit(request: Request) -> None:
    """Reject when the per-fingerprint attempt counter exceeds the per-minute budget.

    Backed by :mod:`agent_bom.api.shared_auth_state` so a clustered
    deployment with ``AGENT_BOM_POSTGRES_URL`` set enforces the limit
    cross-replica via Postgres, instead of the per-process dict the
    pre-PR-C path used (audit-5 PR-A landed a runtime warning for
    that gap; this PR closes it).
    """
    from agent_bom.api.shared_auth_state import AuthStateUnavailable, get_auth_state

    backend = get_auth_state()
    key = _client_fingerprint(request)
    try:
        allowed = backend.record_attempt(key, window_seconds=60, limit=_auth_session_limit())
    except AuthStateUnavailable as exc:
        raise HTTPException(status_code=503, detail="Authentication state unavailable") from exc
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many browser session attempts")


def _saml_relay_ttl_seconds() -> int:
    raw = (env_raw("AGENT_BOM_SAML_RELAY_STATE_TTL_SECONDS") or "300").strip()
    try:
        return max(60, min(int(raw), 900))
    except ValueError:
        return 300


def _relay_state_digest(relay_state: str) -> str:
    import hashlib

    return hashlib.sha256(relay_state.encode("utf-8")).hexdigest()


def _saml_response_digest(saml_response: str) -> str:
    """Hash the verified response bytes, independent of Base64 presentation."""
    import hashlib

    compact = "".join(saml_response.split())
    try:
        response_bytes = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        # Production reaches this helper only after python3-saml has verified
        # the response. Keep mocked/test integrations deterministic without weakening the verification boundary.
        response_bytes = compact.encode("utf-8")
    return hashlib.sha256(response_bytes).hexdigest()


def _saml_idp_initiated_allowed() -> bool:
    return env_raw("AGENT_BOM_SAML_ALLOW_IDP_INITIATED", "").strip().lower() in {"1", "true", "yes", "on"}


def _saml_relay_nonce(relay_state: str) -> str:
    return f"saml-relay:{_relay_state_digest(relay_state)}"


def _new_saml_relay_state() -> tuple[str, str]:
    from agent_bom.api.shared_auth_state import AuthStateUnavailable, get_auth_state

    backend = get_auth_state()
    ttl = _saml_relay_ttl_seconds()
    now = int(time.time())
    expires_at = now + ttl
    for _ in range(3):
        relay_state = secrets.token_urlsafe(32)
        try:
            if backend.register_one_time_nonce(_saml_relay_nonce(relay_state), expires_at, now=now):
                return relay_state, (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat()
        except AuthStateUnavailable as exc:
            raise HTTPException(status_code=503, detail="Authentication state unavailable") from exc
    raise HTTPException(status_code=503, detail="SAML relay_state issuance unavailable")


def _consume_saml_relay_state(relay_state: str | None) -> None:
    if not relay_state:
        if _saml_idp_initiated_allowed():
            return
        raise HTTPException(status_code=401, detail="SAML relay_state required")
    from agent_bom.api.shared_auth_state import AuthStateUnavailable, get_auth_state

    backend = get_auth_state()
    now = int(time.time())
    try:
        redeemed = backend.redeem_one_time_nonce(_saml_relay_nonce(relay_state), now=now)
    except AuthStateUnavailable as exc:
        raise HTTPException(status_code=503, detail="Authentication state unavailable") from exc
    if not redeemed:
        raise HTTPException(status_code=401, detail="Invalid or expired SAML relay_state")


def _consume_saml_response_once(saml_response: str, *, ttl_seconds: int) -> None:
    from agent_bom.api.shared_auth_state import AuthStateUnavailable, get_auth_state

    digest = f"saml-response:{_saml_response_digest(saml_response)}"
    backend = get_auth_state()
    now = int(time.time())
    try:
        consumed = backend.consume_nonce_once(digest, now + max(60, int(ttl_seconds)), now=now)
    except AuthStateUnavailable as exc:
        raise HTTPException(status_code=503, detail="Authentication state unavailable") from exc
    if not consumed:
        raise HTTPException(status_code=401, detail="SAML assertion replay detected")


def _auth_session_state(request: Request) -> dict:
    """Build the current request's auth/session state without leaking secrets."""
    from agent_bom.api.auth_posture import get_auth_runtime_status
    from agent_bom.rbac import summarize_role

    method = getattr(request.state, "auth_method", None)
    subject = getattr(request.state, "api_key_name", None)
    role = getattr(request.state, "api_key_role", None)
    tenant_id = getattr(request.state, "tenant_id", None) or "default"
    request_id = getattr(request.state, "request_id", None)
    trace_id = getattr(request.state, "trace_id", None)
    span_id = getattr(request.state, "span_id", None)
    issuer = getattr(request.state, "auth_issuer", None)
    key_id = getattr(request.state, "api_key_id", None)
    key_id_prefix = key_id[:8] if isinstance(key_id, str) else None

    authenticated = bool(method and role)
    auth_runtime = get_auth_runtime_status()
    role_summary = summarize_role(role)

    sso_provider = None
    configured_modes = auth_runtime.get("configured_modes")
    if isinstance(configured_modes, list) and "oidc_browser" in configured_modes:
        from agent_bom.api.oidc_browser import configured_browser_sso_provider

        sso_provider = configured_browser_sso_provider()

    return {
        "authenticated": authenticated,
        "auth_required": auth_runtime["auth_required"],
        "configured_modes": auth_runtime["configured_modes"],
        "recommended_ui_mode": auth_runtime["recommended_ui_mode"],
        "sso_provider": sso_provider,
        "auth_method": method,
        "subject": subject,
        "role": role,
        "tenant_id": tenant_id,
        "oidc_issuer_suffix": issuer,
        "api_key_id_prefix": key_id_prefix,
        "request_id": request_id,
        "trace_id": trace_id,
        "span_id": span_id,
        "role_summary": role_summary,
    }


def _session_cookie_secure(request: Request) -> bool:
    raw = env_raw("AGENT_BOM_SESSION_COOKIE_SECURE", "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    from agent_bom.api.middleware import _production_or_clustered_control_plane

    if _production_or_clustered_control_plane():
        return True
    trusted_proxy = env_raw("AGENT_BOM_TRUST_PROXY_AUTH", "").strip().lower() in {"1", "true", "yes", "on"}
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower() if trusted_proxy else ""
    return request.url.scheme == "https" or forwarded_proto == "https"


def _session_cookie_max_age() -> int:
    raw = env_raw("AGENT_BOM_SESSION_COOKIE_MAX_AGE_SECONDS", "").strip()
    if not raw:
        return 8 * 60 * 60
    try:
        parsed = int(raw)
    except ValueError:
        return 8 * 60 * 60
    return max(60, min(parsed, 24 * 60 * 60))


def _set_browser_session_cookie(
    response: Response,
    request: Request,
    *,
    subject: str,
    role: str,
    tenant_id: str,
    auth_method: str,
    key_id: str | None = None,
    scopes: list[str] | None = None,
) -> None:
    from agent_bom.api.browser_session import (
        CSRF_COOKIE_NAME,
        SESSION_COOKIE_NAME,
        SIGNED_OUT_COOKIE_NAME,
        BrowserSessionError,
        create_browser_session_token,
    )

    max_age = _session_cookie_max_age()
    try:
        token, csrf = create_browser_session_token(
            subject=subject,
            role=role,
            tenant_id=tenant_id,
            auth_method=auth_method,
            key_id=key_id,
            scopes=scopes,
            max_age_seconds=max_age,
        )
    except BrowserSessionError as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc, generic=True)) from exc
    secure = _session_cookie_secure(request)
    response.delete_cookie(SIGNED_OUT_COOKIE_NAME, httponly=True, secure=secure, samesite="strict", path="/")
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE_NAME,
        csrf,
        max_age=max_age,
        httponly=False,
        secure=secure,
        samesite="strict",
        path="/",
    )


def _delete_browser_session_cookies(response: Response, request: Request) -> None:
    from agent_bom.api.browser_session import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME, SIGNED_OUT_COOKIE_NAME

    secure = _session_cookie_secure(request)
    # Non-authorizing intent marker: survive navigation until explicit sign-in.
    response.set_cookie(SIGNED_OUT_COOKIE_NAME, "1", max_age=365 * 24 * 60 * 60, httponly=True, secure=secure, samesite="strict", path="/")
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )
    response.delete_cookie(
        CSRF_COOKIE_NAME,
        httponly=False,
        secure=secure,
        samesite="strict",
        path="/",
    )


def _clear_browser_session_cookie(response: Response, request: Request) -> None:
    from agent_bom.api.browser_session import SESSION_COOKIE_NAME, revoke_browser_session_token
    from agent_bom.api.shared_auth_state import AuthStateUnavailable

    try:
        revoke_browser_session_token(request.cookies.get(SESSION_COOKIE_NAME, ""))
    except AuthStateUnavailable as exc:
        raise HTTPException(status_code=503, detail="Authentication state unavailable") from exc
    _delete_browser_session_cookies(response, request)


def _loopback_browser_origin(request: Request) -> bool:
    """Return whether a browser request originated from a loopback UI.

    The zero-config dev-session exchange is deliberately browser-only.  An
    explicit loopback Origin prevents an unrelated web page from using the
    operator's local API as a session-minting CSRF target.
    """
    origin = request.headers.get("origin", "").strip()
    if not origin:
        return False
    try:
        hostname = (urlsplit(origin).hostname or "").lower()
    except ValueError:
        return False
    return hostname in {"localhost", "127.0.0.1", "::1"}


_DEV_SESSION_MAX_AGE_SECONDS = 8 * 60 * 60


def _maybe_attach_dev_session_cookie(response: Any, request: Request) -> None:
    """Seed a loopback browser session so the zero-config dev key authenticates
    the same-origin dashboard without any flag or manual key entry.

    No-op unless an ephemeral dev key is active. The dev key is only ever set on
    a loopback bind (the CLI auth gate refuses non-loopback binds before the key
    is generated), so a set key already means "loopback, no other auth". The
    minted session carries no ``key_id``, so it stays valid for the process
    lifetime without depending on key-store lookups, and is re-used across page
    loads instead of churning a fresh nonce each request.
    """
    if get_dev_api_key() is None or not _host_guard.is_loopback_hostname(
        _host_guard.hostname_from_authority(request.headers.get("host", ""))
    ):
        return
    from agent_bom.api.browser_session import (
        CSRF_COOKIE_NAME,
        SESSION_COOKIE_NAME,
        SIGNED_OUT_COOKIE_NAME,
        BrowserSessionError,
        create_browser_session_token,
        verify_browser_session_token,
    )

    if request.cookies.get(SIGNED_OUT_COOKIE_NAME) == "1":
        return
    existing = request.cookies.get(SESSION_COOKIE_NAME, "")
    if existing:
        try:
            verify_browser_session_token(existing)
            return
        except BrowserSessionError:
            pass
    try:
        token, csrf = create_browser_session_token(
            subject="loopback-dev-key",
            role=get_dev_api_role().value,
            tenant_id="default",
            auth_method="browser_session_dev_key",
            key_id=None,
            scopes=[],
            max_age_seconds=_DEV_SESSION_MAX_AGE_SECONDS,
        )
    except BrowserSessionError:
        return
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=_DEV_SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=False,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE_NAME,
        csrf,
        max_age=_DEV_SESSION_MAX_AGE_SECONDS,
        httponly=False,
        secure=False,
        samesite="strict",
        path="/",
    )
