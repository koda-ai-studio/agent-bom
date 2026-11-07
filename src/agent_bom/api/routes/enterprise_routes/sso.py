"""Snowflake OAuth and SAML single sign-on routes."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable, Coroutine
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from urllib.parse import parse_qs, urlsplit

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.routing import APIRoute

from agent_bom.api import audit_log
from agent_bom.api import saml as saml_api
from agent_bom.api.browser_session import BrowserSessionError, open_saml_login, seal_saml_login
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
from agent_bom.core.settings import env_raw
from agent_bom.security import sanitize_error, sanitize_text

router = APIRouter()

SAML_FORM_MAX_BYTES = 1024 * 1024
SAML_LOGIN_COOKIE = "__Host-agent_bom_saml_login"
SAML_LOGIN_COOKIE_LOCAL = "agent_bom_saml_login"
_NO_STORE = {"Cache-Control": "no-cache, no-store"}
_SAML_FORM_MAX_FIELDS = 8
_SAML_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"


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
    audit_log.log_action(
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

    if not saml_api.saml_runtime_available():
        raise HTTPException(
            status_code=503,
            detail=f"SAML SSO requires the optional [saml] extra. Install with: {saml_api.SAML_INSTALL_HINT}",
        )
    try:
        metadata = saml_api.SAMLConfig.from_env().metadata_xml()
    except saml_api.SAMLError as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc)) from exc
    return PlainTextResponse(content=metadata, media_type="application/samlmetadata+xml")


@router.post("/auth/saml/relay-state", tags=["enterprise"])
def saml_relay_state() -> dict:
    """Issue a one-time RelayState nonce for SP-initiated SAML login."""
    if reason := saml_api.saml_unavailable_reason():
        raise HTTPException(status_code=503, detail=reason)
    relay_state, expires_at = _new_saml_relay_state()
    return {
        "relay_state": relay_state,
        "expires_at": expires_at,
        "ttl_seconds": _saml_relay_ttl_seconds(),
    }


def _verify_saml_login(req: SAMLLoginRequest, *, request_id: str | None = None) -> tuple[Any, Any]:

    if not saml_api.saml_runtime_available():
        raise HTTPException(
            status_code=503,
            detail=f"SAML SSO requires the optional [saml] extra. Install with: {saml_api.SAML_INSTALL_HINT}",
        )
    try:
        _consume_saml_relay_state(req.relay_state)
        cfg = saml_api.SAMLConfig.from_env()
        bound = {} if request_id is None else {"request_id": request_id}
        assertion = cfg.verify_response(req.saml_response, relay_state=req.relay_state, **bound)
        _consume_saml_response_once(req.saml_response, ttl_seconds=cfg.session_ttl_seconds)
    except saml_api.SAMLError as exc:
        raise HTTPException(status_code=401, detail=sanitize_error(exc)) from exc
    return cfg, assertion


def _mint_saml_key(cfg: Any, assertion: Any) -> tuple[str, Any]:
    from agent_bom.api.auth import Role, create_api_key, resolve_scim_user_role

    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=cfg.session_ttl_seconds)).isoformat()
    scim_resolution = resolve_scim_user_role(assertion.tenant_id, assertion.subject)
    scim_subject_id = scim_resolution.user_id if scim_resolution.user_id else assertion.subject
    return create_api_key(
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


def _record_saml_login(api_key: Any, assertion: Any) -> None:
    from agent_bom.api.auth import get_key_store

    get_key_store().add(api_key)
    audit_log.log_action(
        "auth.saml_login",
        actor=assertion.subject,
        resource=f"key/{api_key.key_id}",
        role=assertion.role,
        tenant_id=assertion.tenant_id,
        session_index=assertion.session_index,
    )


def saml_login(req: SAMLLoginRequest) -> dict:
    """Verify a SAML assertion and return a short-lived API key."""
    cfg, assertion = _verify_saml_login(req)
    raw_key, api_key = _mint_saml_key(cfg, assertion)
    _record_saml_login(api_key, assertion)
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


async def _read_saml_form(request: Request) -> SAMLLoginRequest:
    """Parse the HTTP-POST binding from a bounded body; unknown controls are ignored, as the binding allows."""
    raw = bytearray()
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > SAML_FORM_MAX_BYTES:
            raise HTTPException(status_code=413, detail="SAML form exceeds the size limit")
    try:
        fields = parse_qs(
            raw.decode("ascii"),
            keep_blank_values=True,
            strict_parsing=bool(raw),
            max_num_fields=_SAML_FORM_MAX_FIELDS,
            errors="strict",
        )
    except ValueError:
        raise HTTPException(status_code=422, detail="Malformed SAML form") from None
    responses = fields.get("SAMLResponse", [])
    relay_states = fields.get("RelayState", [])
    if len(responses) != 1 or not responses[0].strip() or len(relay_states) > 1:
        raise HTTPException(status_code=422, detail="SAML form requires one SAMLResponse and at most one RelayState")
    return SAMLLoginRequest(saml_response=responses[0], relay_state=relay_states[0] if relay_states else None)


def _saml_login_cookie(sp_acs_url: str) -> tuple[str, Literal["none", "lax"]]:
    """The cookie that binds a browser to its login, and its SameSite mode.

    The IdP's form post arrives cross-site, which only SameSite=None survives,
    and browsers require Secure with it. Plain-http local development has neither,
    so it uses a separate cookie that an https deployment never reads.
    """
    from agent_bom.api.middleware import _production_or_clustered_control_plane

    if urlsplit(sp_acs_url).scheme.lower() == "https":
        return SAML_LOGIN_COOKIE, "none"
    if _production_or_clustered_control_plane():
        raise HTTPException(status_code=503, detail="SAML browser login requires an https AGENT_BOM_SAML_SP_ACS_URL")
    return SAML_LOGIN_COOKIE_LOCAL, "lax"


def _clear_saml_login_cookie(response: Response, name: str, samesite: Literal["none", "lax"]) -> None:
    response.delete_cookie(name, path="/", secure=name == SAML_LOGIN_COOKIE, httponly=True, samesite=samesite)


@router.get(
    "/auth/saml/start",
    tags=["enterprise"],
    status_code=302,
    response_class=RedirectResponse,
    responses={302: {"description": "Redirect to the IdP with a new AuthnRequest; the browser is bound to this login by a cookie."}},
)
def saml_login_start(request: Request) -> RedirectResponse:
    """Start SP-initiated SAML browser login."""

    _check_auth_session_rate_limit(request)
    if reason := saml_api.saml_unavailable_reason():
        raise HTTPException(status_code=503, detail=reason)
    cfg = saml_api.SAMLConfig.from_env()
    name, samesite = _saml_login_cookie(cfg.sp_acs_url)
    relay_state, _expires_at = _new_saml_relay_state()
    try:
        redirect_url, request_id = cfg.begin_login(relay_state)
        sealed = seal_saml_login(relay_state, request_id)
    except (saml_api.SAMLError, BrowserSessionError) as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc)) from exc
    response = RedirectResponse(url=redirect_url, status_code=302, headers=_NO_STORE)
    response.set_cookie(
        name,
        sealed,
        max_age=_saml_relay_ttl_seconds(),
        path="/",
        secure=name == SAML_LOGIN_COOKIE,
        httponly=True,
        samesite=samesite,
    )
    return response


def _saml_browser_login(request: Request, req: SAMLLoginRequest) -> Response:
    """Finish an IdP form post from the browser that started this login.

    The key backs an HttpOnly session and never reaches the page. The redirect
    target is fixed: RelayState only redeems a server-issued one-time nonce.
    """

    if reason := saml_api.saml_unavailable_reason():
        raise HTTPException(status_code=503, detail=reason)
    _check_auth_session_rate_limit(request)
    name, samesite = _saml_login_cookie(saml_api.SAMLConfig.from_env().sp_acs_url)
    request_id = open_saml_login(request.cookies.get(name, ""), req.relay_state or "")
    if request_id is None:
        raise HTTPException(
            status_code=401, detail="SAML form post must come from the browser that started the login at /v1/auth/saml/start"
        )
    response: Response
    try:
        cfg, assertion = _verify_saml_login(req, request_id=request_id)
        _raw_key, api_key = _mint_saml_key(cfg, assertion)
        response = RedirectResponse(url="/", status_code=303, headers=_NO_STORE)
        _set_browser_session_cookie(
            response,
            request,
            subject=api_key.name,
            role=api_key.role.value,
            tenant_id=api_key.tenant_id,
            auth_method="saml",
            key_id=api_key.key_id,
            scopes=[],
        )
        _record_saml_login(api_key, assertion)
    except HTTPException as exc:
        response = JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=_NO_STORE)
    _clear_saml_login_cookie(response, name, samesite)
    return response


class _SAMLAssertionConsumerRoute(APIRoute):
    """Serve the SAML HTTP-POST binding beside the typed JSON contract on one path."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        json_handler = super().get_route_handler()

        async def handler(request: Request) -> Response:
            content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if content_type != _SAML_FORM_CONTENT_TYPE:
                return await json_handler(request)
            login = await _read_saml_form(request)
            return await anyio.to_thread.run_sync(_saml_browser_login, request, login)

        return handler


router.add_api_route(
    "/auth/saml/login",
    saml_login,
    methods=["POST"],
    tags=["enterprise"],
    status_code=201,
    route_class_override=_SAMLAssertionConsumerRoute,
    responses={
        303: {"description": "IdP form post verified: browser session started, redirected to the dashboard."},
        413: {"description": "SAML form exceeds the size limit."},
    },
    openapi_extra={
        "requestBody": {
            "content": {
                _SAML_FORM_CONTENT_TYPE: {
                    "schema": {
                        "type": "object",
                        "required": ["SAMLResponse", "RelayState"],
                        "properties": {"SAMLResponse": {"type": "string"}, "RelayState": {"type": "string"}},
                    }
                }
            }
        }
    },
)
