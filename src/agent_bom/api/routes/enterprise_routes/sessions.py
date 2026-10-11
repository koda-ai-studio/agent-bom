"""Auth introspection and managed-trial / OIDC browser login routes."""

from __future__ import annotations

import secrets
import time
from typing import Any
from urllib.parse import urlsplit

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import SecretStr

from agent_bom.api.read_models import AuthMeResponse, documented
from agent_bom.api.read_models.enterprise import AuthDebugResponse
from agent_bom.api.routes.enterprise_routes._models import ManagedTrialOIDCStartRequest
from agent_bom.api.routes.enterprise_routes._session_helpers import (
    _auth_session_state,
    _check_auth_session_rate_limit,
    _relay_state_digest,
    _session_cookie_secure,
)
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.core.settings import env_raw
from agent_bom.security import sanitize_error

router = APIRouter()


@router.get("/auth/debug", **documented(AuthDebugResponse), tags=["enterprise"])
def auth_debug(request: Request) -> dict:
    """Introspect how the current request was authenticated.

    Surfaces the auth method (``static_api_key`` / ``api_key`` / ``oidc`` /
    ``saml``), the resolved role + tenant, the request-scoped trace IDs, and
    the subject recorded for audit purposes. Intended for operator support
    flows — "why is my request being denied?" — and for client SDKs doing
    session introspection without issuing a shadow request.

    The response never contains the raw API key or OIDC token. Only
    non-secret identifying attributes (name, key_id prefix, role, tenant,
    auth method) so the endpoint is safe to log.
    """
    state = _auth_session_state(request)
    return {
        "authenticated": state["authenticated"],
        "auth_required": state["auth_required"],
        "configured_modes": state["configured_modes"],
        "recommended_ui_mode": state["recommended_ui_mode"],
        "auth_method": state["auth_method"],
        "subject": state["subject"],
        "role": state["role"],
        "tenant_id": state["tenant_id"],
        "oidc_issuer_suffix": state["oidc_issuer_suffix"],
        "api_key_id_prefix": state["api_key_id_prefix"],
        "request_id": state["request_id"],
        "trace_id": state["trace_id"],
        "span_id": state["span_id"],
    }


@router.get("/auth/me", **documented(AuthMeResponse), tags=["enterprise"])
def auth_me(request: Request) -> dict:
    """Return the current UI-facing actor/session contract for the active tenant."""
    from agent_bom.api.managed_trial import managed_trial_enabled, managed_trial_envelope

    state = _auth_session_state(request)
    role_summary = state["role_summary"]
    memberships = []
    if role_summary is not None:
        memberships.append(
            {
                "tenant_id": state["tenant_id"],
                "role": role_summary["role"],
                "ui_role": role_summary["ui_role"],
                "display_name": role_summary["display_name"],
                "active": True,
            }
        )

    return {
        "authenticated": state["authenticated"],
        "auth_required": state["auth_required"],
        "configured_modes": state["configured_modes"],
        "recommended_ui_mode": state["recommended_ui_mode"],
        "sso_provider": state["sso_provider"],
        "auth_method": state["auth_method"],
        "managed_trial_mode": managed_trial_enabled(),
        "managed_trial_envelope": managed_trial_envelope(),
        "subject": state["subject"],
        "tenant_id": state["tenant_id"],
        "role": state["role"],
        "role_summary": role_summary,
        "memberships": memberships,
        "request_id": state["request_id"],
        "trace_id": state["trace_id"],
        "span_id": state["span_id"],
    }


@router.delete("/auth/keys/{key_id}", tags=["enterprise"], status_code=204)
def delete_key(request: Request, key_id: str) -> None:
    """Revoke an API key."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import get_key_store

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "")
    store = get_key_store()
    key = store.get(key_id)
    if key is None or key.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail=f"Key {key_id} not found")
    store.remove(key_id)

    log_action("auth.key_revoked", actor=actor, resource=f"key/{key_id}", tenant_id=tenant_id)


def _oidc_login_nonce(state: str) -> str:
    return f"oidc-login:{_relay_state_digest(state)}"


def _new_oidc_login_state() -> str:
    from agent_bom.api.shared_auth_state import AuthStateUnavailable, get_auth_state

    backend = get_auth_state()
    ttl = int(env_raw("AGENT_BOM_OIDC_LOGIN_STATE_TTL_SECONDS") or "300")
    try:
        ttl = max(60, min(ttl, 900))
    except (TypeError, ValueError):
        ttl = 300
    now = int(time.time())
    expires_at = now + ttl
    for _ in range(3):
        state = secrets.token_urlsafe(32)
        try:
            if backend.register_one_time_nonce(_oidc_login_nonce(state), expires_at, now=now):
                return state
        except AuthStateUnavailable as exc:
            raise HTTPException(status_code=503, detail="Authentication state unavailable") from exc
    raise HTTPException(status_code=503, detail="OIDC login state issuance unavailable")


def _consume_oidc_login_state(state: str | None) -> None:
    if not state:
        raise HTTPException(status_code=401, detail="OIDC state required")
    from agent_bom.api.shared_auth_state import AuthStateUnavailable, get_auth_state

    backend = get_auth_state()
    now = int(time.time())
    try:
        redeemed = backend.redeem_one_time_nonce(_oidc_login_nonce(state), now=now)
    except AuthStateUnavailable as exc:
        raise HTTPException(status_code=503, detail="Authentication state unavailable") from exc
    if not redeemed:
        raise HTTPException(status_code=401, detail="Invalid or expired OIDC state")


def _safe_post_login_path(raw: str | None) -> str:
    normalized = (raw or "/").strip().replace("\\", "/") or "/"
    parsed = urlsplit(normalized)
    if parsed.scheme or parsed.netloc:
        return "/"
    local_path = parsed.path or "/"
    if not local_path.startswith("/") or local_path.startswith("//"):
        return "/"
    suffix = f"?{parsed.query}" if parsed.query else ""
    if parsed.fragment:
        suffix += f"#{parsed.fragment}"
    return f"{local_path}{suffix}"


def _allowed_post_login_path(raw: str | None) -> str:
    safe_path = _safe_post_login_path(raw)
    parsed = urlsplit(safe_path)
    base_path = parsed.path or "/"
    allowed_paths = {
        "/",
        "/dashboard",
        "/findings",
        "/exceptions",
        "/baselines",
        "/trends",
        "/settings",
    }
    if base_path not in allowed_paths:
        return "/"
    suffix = f"?{parsed.query}" if parsed.query else ""
    if parsed.fragment:
        suffix += f"#{parsed.fragment}"
    return f"{base_path}{suffix}"


@router.post("/auth/trial/oidc/start", tags=["enterprise"])
async def managed_trial_oidc_start(request: Request, body: ManagedTrialOIDCStartRequest) -> RedirectResponse:
    """Validate a posted one-time invitation and start OIDC PKCE authentication."""
    import hashlib

    from agent_bom.api.managed_trial_invitation import (
        ManagedTrialInvitationConfigurationError,
        ManagedTrialInvitationError,
        get_managed_trial_invitation_store,
        managed_trial_invitations_enabled,
    )
    from agent_bom.api.oidc import OIDCError
    from agent_bom.api.oidc_browser import (
        OIDC_PKCE_COOKIE_NAME,
        OIDCBrowserConfig,
        build_authorize_url,
        pkce_challenge_s256,
        pkce_verifier,
        seal_pkce_cookie,
    )

    if not managed_trial_invitations_enabled():
        raise HTTPException(status_code=404, detail="Not found")
    _check_auth_session_rate_limit(request)
    raw_token = body.token.get_secret_value()
    if not raw_token.startswith("abti_") or len(raw_token) > 128:
        raise HTTPException(status_code=401, detail="Invalid or expired managed-trial invitation")
    digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    def _load_invitation() -> Any:
        return get_managed_trial_invitation_store().get_by_digest(digest)

    try:
        await anyio.to_thread.run_sync(_load_invitation)
    except ManagedTrialInvitationConfigurationError as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc, generic=True)) from exc
    except ManagedTrialInvitationError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired managed-trial invitation") from exc
    try:
        cfg = OIDCBrowserConfig.from_env()
    except OIDCError as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc, generic=True)) from exc
    if not cfg.enabled:
        raise HTTPException(status_code=503, detail="OIDC browser SSO is not configured")

    state = _new_oidc_login_state()
    nonce = secrets.token_urlsafe(32)
    verifier = pkce_verifier()
    try:
        authorize_url = build_authorize_url(
            cfg,
            state=state,
            nonce=nonce,
            code_challenge=pkce_challenge_s256(verifier),
        )
        sealed = seal_pkce_cookie(
            code_verifier=verifier,
            nonce=nonce,
            managed_trial_invitation_digest=digest,
        )
    except OIDCError as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc, generic=True)) from exc

    response = RedirectResponse(url=authorize_url, status_code=302)
    response.set_cookie(
        OIDC_PKCE_COOKIE_NAME,
        sealed,
        max_age=300,
        httponly=True,
        secure=_session_cookie_secure(request),
        samesite="lax",
        path="/",
    )
    return response


@router.post("/auth/trial/oidc/start-form", include_in_schema=False)
async def managed_trial_oidc_start_form(request: Request) -> RedirectResponse:
    """Browser form adapter that keeps the invitation secret out of the URL.

    The public JSON contract above remains the typed API.  This adapter accepts
    only a bounded ``application/x-www-form-urlencoded`` body from ``/login``
    and immediately delegates to the same validation and PKCE path.
    """

    from urllib.parse import parse_qs

    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        raise HTTPException(status_code=415, detail="Unsupported invitation form content type")
    raw = await request.body()
    if len(raw) > 512:
        raise HTTPException(status_code=401, detail="Invalid or expired managed-trial invitation")
    try:
        token = parse_qs(raw.decode("utf-8"), strict_parsing=True).get("token", [""])[0]
        body = ManagedTrialOIDCStartRequest(token=SecretStr(token))
    except (UnicodeDecodeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired managed-trial invitation") from None
    return await managed_trial_oidc_start(request, body)


@router.get("/auth/oidc/login", tags=["enterprise"])
def oidc_browser_login(request: Request, return_to: str | None = None) -> RedirectResponse:
    """Start OIDC authorization-code + PKCE login for the dashboard."""
    from agent_bom.api.oidc import OIDCError
    from agent_bom.api.oidc_browser import (
        OIDC_PKCE_COOKIE_NAME,
        OIDCBrowserConfig,
        build_authorize_url,
        pkce_challenge_s256,
        pkce_verifier,
        seal_pkce_cookie,
    )

    _check_auth_session_rate_limit(request)
    try:
        cfg = OIDCBrowserConfig.from_env()
    except OIDCError as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc)) from exc
    if not cfg.enabled:
        raise HTTPException(
            status_code=503,
            detail="OIDC browser SSO requires AGENT_BOM_OIDC_ISSUER, AGENT_BOM_OIDC_CLIENT_ID, and AGENT_BOM_OIDC_REDIRECT_URI",
        )

    state = _new_oidc_login_state()
    nonce = secrets.token_urlsafe(32)
    verifier = pkce_verifier()
    challenge = pkce_challenge_s256(verifier)
    try:
        authorize_url = build_authorize_url(cfg, state=state, nonce=nonce, code_challenge=challenge)
        sealed = seal_pkce_cookie(
            code_verifier=verifier,
            nonce=nonce,
        )
    except OIDCError as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc)) from exc

    response = RedirectResponse(url=authorize_url, status_code=302)
    secure = _session_cookie_secure(request)
    response.set_cookie(
        OIDC_PKCE_COOKIE_NAME,
        sealed,
        max_age=300,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )
    return response
