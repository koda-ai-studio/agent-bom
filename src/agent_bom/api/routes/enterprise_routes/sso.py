"""Snowflake OAuth and SAML single sign-on routes."""

from __future__ import annotations

import secrets
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse

from agent_bom.api.models import SAMLLoginRequest
from agent_bom.api.routes.enterprise_routes._session_helpers import (
    _check_auth_session_rate_limit,
    _consume_saml_relay_state,
    _consume_saml_response_once,
    _new_saml_relay_state,
    _relay_state_digest,
    _saml_relay_ttl_seconds,
    _session_cookie_secure,
    _set_browser_session_cookie,
)
from agent_bom.api.saml import saml_unavailable_reason
from agent_bom.core.settings import env_raw
from agent_bom.security import sanitize_error, sanitize_text

router = APIRouter()


def _snowflake_login_nonce(state: str) -> str:
    return f"snowflake-oauth-login:{_relay_state_digest(state)}"


def _new_snowflake_login_state() -> str:
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
            if backend.register_one_time_nonce(_snowflake_login_nonce(state), expires_at, now=now):
                return state
        except AuthStateUnavailable as exc:
            raise HTTPException(status_code=503, detail="Authentication state unavailable") from exc
    raise HTTPException(status_code=503, detail="Snowflake OAuth login state issuance unavailable")


def _consume_snowflake_login_state(state: str | None) -> None:
    if not state:
        raise HTTPException(status_code=401, detail="Snowflake OAuth state required")
    from agent_bom.api.shared_auth_state import AuthStateUnavailable, get_auth_state

    backend = get_auth_state()
    now = int(time.time())
    try:
        redeemed = backend.redeem_one_time_nonce(_snowflake_login_nonce(state), now=now)
    except AuthStateUnavailable as exc:
        raise HTTPException(status_code=503, detail="Authentication state unavailable") from exc
    if not redeemed:
        raise HTTPException(status_code=401, detail="Invalid or expired Snowflake OAuth state")


@router.get("/auth/snowflake/login", tags=["enterprise"])
def snowflake_oauth_login(request: Request) -> RedirectResponse:
    """Start Snowflake OAuth authorization-code + PKCE sign-in for the dashboard."""
    from agent_bom.api.oidc import OIDCError
    from agent_bom.api.oidc_browser import (
        OIDC_PKCE_COOKIE_NAME,
        pkce_challenge_s256,
        pkce_verifier,
        seal_pkce_cookie,
    )
    from agent_bom.api.snowflake_oauth import SnowflakeOAuthConfig, build_authorize_url

    _check_auth_session_rate_limit(request)
    try:
        cfg = SnowflakeOAuthConfig.from_env()
    except OIDCError as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc)) from exc
    if not cfg.enabled:
        raise HTTPException(
            status_code=503,
            detail=(
                "Snowflake OAuth sign-in requires AGENT_BOM_SNOWFLAKE_OAUTH_ACCOUNT_URL, "
                "AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_ID, and AGENT_BOM_SNOWFLAKE_OAUTH_REDIRECT_URI"
            ),
        )

    state = _new_snowflake_login_state()
    verifier = pkce_verifier()
    challenge = pkce_challenge_s256(verifier)
    try:
        authorize_url = build_authorize_url(cfg, state=state, code_challenge=challenge)
        sealed = seal_pkce_cookie(code_verifier=verifier, nonce=secrets.token_urlsafe(16))
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


@router.get("/auth/snowflake/callback", tags=["enterprise"])
def snowflake_oauth_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> RedirectResponse:
    """Complete Snowflake OAuth sign-in and mint a browser session cookie.

    Snowflake's OAuth server is non-standard: no ID token, JWKS, or userinfo.
    Identity is the ``username`` returned by the token endpoint (fail closed if
    absent). Role defaults to the configured least-privilege role and is only
    elevated by an explicit SCIM mapping for the user.
    """
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import Role, resolve_scim_user_role
    from agent_bom.api.oidc import OIDCError
    from agent_bom.api.oidc_browser import OIDC_PKCE_COOKIE_NAME, open_pkce_cookie
    from agent_bom.api.snowflake_oauth import (
        SnowflakeOAuthConfig,
        exchange_code_for_tokens,
        username_from_token_response,
    )

    _check_auth_session_rate_limit(request)
    if error:
        detail = sanitize_text(error_description or error)
        raise HTTPException(status_code=401, detail=f"Snowflake OAuth login failed: {detail}")
    if not code:
        raise HTTPException(status_code=401, detail="Snowflake OAuth authorization code required")

    _consume_snowflake_login_state(state)
    sealed = request.cookies.get(OIDC_PKCE_COOKIE_NAME, "")
    if not sealed:
        raise HTTPException(status_code=401, detail="Snowflake OAuth PKCE cookie missing")

    try:
        cfg = SnowflakeOAuthConfig.from_env()
        code_verifier, _nonce, _return_to = open_pkce_cookie(sealed)
        token_payload = exchange_code_for_tokens(cfg, code=code, code_verifier=code_verifier)
        subject = username_from_token_response(token_payload)
    except OIDCError as exc:
        raise HTTPException(status_code=401, detail=sanitize_error(exc)) from exc

    tenant_id = cfg.tenant_id
    try:
        default_role = Role(cfg.default_role).value
    except ValueError:
        default_role = Role.VIEWER.value
    scim_resolution = resolve_scim_user_role(tenant_id, subject)
    effective_role = scim_resolution.role.value if scim_resolution.role is not None else default_role
    try:
        role_value = Role(effective_role).value
    except ValueError:
        role_value = Role.VIEWER.value

    response = RedirectResponse(url="/", status_code=302)
    _set_browser_session_cookie(
        response,
        request,
        subject=subject,
        role=role_value,
        tenant_id=tenant_id,
        auth_method="snowflake_oauth",
        scopes=["snowflake-oauth-session"],
    )
    secure = _session_cookie_secure(request)
    response.delete_cookie(OIDC_PKCE_COOKIE_NAME, httponly=True, secure=secure, samesite="lax", path="/")
    log_action(
        "auth.snowflake_oauth_login",
        actor=subject,
        resource="auth/snowflake",
        tenant_id=tenant_id,
        details={"role": role_value, "auth_method": "snowflake_oauth"},
    )
    return response


@router.get("/auth/saml/metadata", tags=["enterprise"])
def saml_metadata() -> PlainTextResponse:
    """Return SP metadata XML for enterprise IdP configuration."""
    from agent_bom.api.saml import SAML_INSTALL_HINT, SAMLConfig, SAMLError, saml_runtime_available

    if not saml_runtime_available():
        raise HTTPException(
            status_code=503,
            detail=f"SAML SSO requires the optional [saml] extra. Install with: {SAML_INSTALL_HINT}",
        )
    try:
        metadata = SAMLConfig.from_env().metadata_xml()
    except SAMLError as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc)) from exc
    return PlainTextResponse(content=metadata, media_type="application/samlmetadata+xml")


@router.post("/auth/saml/relay-state", tags=["enterprise"])
def saml_relay_state() -> dict:
    """Issue a one-time RelayState nonce for SP-initiated SAML login."""
    if reason := saml_unavailable_reason():
        raise HTTPException(status_code=503, detail=reason)
    relay_state, expires_at = _new_saml_relay_state()
    return {
        "relay_state": relay_state,
        "expires_at": expires_at,
        "ttl_seconds": _saml_relay_ttl_seconds(),
    }


@router.post("/auth/saml/login", tags=["enterprise"], status_code=201)
def saml_login(req: SAMLLoginRequest) -> dict:
    """Verify a SAML assertion and return a short-lived API key."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import Role, create_api_key, get_key_store, resolve_scim_user_role
    from agent_bom.api.saml import SAML_INSTALL_HINT, SAMLConfig, SAMLError, saml_runtime_available

    if not saml_runtime_available():
        raise HTTPException(
            status_code=503,
            detail=f"SAML SSO requires the optional [saml] extra. Install with: {SAML_INSTALL_HINT}",
        )
    try:
        _consume_saml_relay_state(req.relay_state)
        cfg = SAMLConfig.from_env()
        assertion = cfg.verify_response(req.saml_response, relay_state=req.relay_state)
        _consume_saml_response_once(req.saml_response, ttl_seconds=cfg.session_ttl_seconds)
    except SAMLError as exc:
        raise HTTPException(status_code=401, detail=sanitize_error(exc)) from exc

    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=cfg.session_ttl_seconds)).isoformat()
    scim_resolution = resolve_scim_user_role(assertion.tenant_id, assertion.subject)
    scim_subject_id = scim_resolution.user_id if scim_resolution.user_id else assertion.subject
    raw_key, api_key = create_api_key(
        name=f"saml:{assertion.subject}",
        role=Role(assertion.role),
        expires_at=expires_at,
        # Session provenance is already carried by the ``saml:`` name and
        # auth_method. An empty scope list is the existing explicit
        # role-governed representation; session marker strings must never act
        # as operator-settable scope wildcards.
        scopes=[],
        tenant_id=assertion.tenant_id,
        scim_subject_id=scim_subject_id,
        principal_id=scim_subject_id,
    )
    get_key_store().add(api_key)
    log_action(
        "auth.saml_login",
        actor=assertion.subject,
        resource=f"key/{api_key.key_id}",
        role=assertion.role,
        tenant_id=assertion.tenant_id,
        session_index=assertion.session_index,
    )
    return {
        "raw_key": raw_key,
        "key_id": api_key.key_id,
        "role": api_key.role.value,
        "tenant_id": api_key.tenant_id,
        "subject": assertion.subject,
        "expires_at": api_key.expires_at,
        "attributes": assertion.attributes,
        "message": "Use this short-lived key as Authorization: Bearer <key> for the control-plane session.",
    }
