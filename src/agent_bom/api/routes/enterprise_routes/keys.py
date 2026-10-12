"""Browser session and API key lifecycle routes."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from agent_bom.api.browser_session import SIGNED_OUT_COOKIE_NAME
from agent_bom.api.models import CreateKeyRequest, RotateKeyRequest
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.enterprise import ApiKeysResponse
from agent_bom.api.routes.enterprise_routes._models import BrowserSessionRequest
from agent_bom.api.routes.enterprise_routes._session_helpers import (
    _check_auth_session_rate_limit,
    _clear_browser_session_cookie,
    _delete_browser_session_cookies,
    _loopback_browser_origin,
    _set_browser_session_cookie,
)
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.security import sanitize_error

router = APIRouter()


# ── API Key Management (RBAC) ───────────────────────────────────────────────


@router.post("/auth/dev-session", tags=["enterprise"], status_code=204)
def create_loopback_dev_session(request: Request, response: Response) -> None:
    """Mint the active zero-config loopback session without exposing its key.

    ``agent-bom serve`` enables this only when it generated an ephemeral dev
    key for a loopback bind and no explicit authentication was configured.
    This endpoint lets a separately served local Next.js UI obtain the same
    browser session as the packaged, same-origin dashboard.
    """
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.dev_auth_state import get_dev_api_key, get_dev_api_role

    if get_dev_api_key() is None:
        raise HTTPException(status_code=404, detail="Loopback dev session is not active")
    if not _loopback_browser_origin(request):
        raise HTTPException(status_code=403, detail="Loopback browser origin required")

    if request.cookies.get(SIGNED_OUT_COOKIE_NAME) == "1" and request.headers.get("X-Agent-Bom-Session-Resume") != "true":
        raise HTTPException(status_code=409, detail="Explicit sign-in required after sign-out")

    _set_browser_session_cookie(
        response,
        request,
        subject="loopback-dev-key",
        role=get_dev_api_role().value,
        tenant_id="default",
        auth_method="browser_session_dev_key",
    )
    log_action(
        "auth.browser_session_created",
        actor="loopback-dev-key",
        resource="auth/dev-session",
        tenant_id="default",
        method="loopback_dev_key",
    )
    return None


@router.post("/auth/session", tags=["enterprise"], status_code=204)
async def create_browser_session(request: Request, response: Response, body: BrowserSessionRequest) -> None:
    """Exchange an API key for a same-origin httpOnly browser session cookie.

    This is the dashboard-safe fallback for deployments that are not fronted by
    reverse-proxy OIDC. The raw key is never returned and should be typed only
    into the first-party UI served from the same origin as the API.
    """
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import get_key_store

    _check_auth_session_rate_limit(request)
    raw_key = body.api_key.strip()
    if not raw_key:
        raise HTTPException(status_code=401, detail="Invalid API key")

    from agent_bom.api.secret_source import resolve_secret

    static_key = resolve_secret("AGENT_BOM_API_KEY")
    if static_key and secrets.compare_digest(raw_key, static_key):
        from agent_bom.api.middleware import static_api_key_allowed, static_api_key_rejection_message

        if not static_api_key_allowed():
            raise HTTPException(status_code=503, detail=static_api_key_rejection_message())
        _set_browser_session_cookie(
            response,
            request,
            subject="static-key",
            role="admin",
            tenant_id="default",
            auth_method="browser_session_static_api_key",
        )
        log_action(
            "auth.browser_session_created",
            actor="static-key",
            resource="auth/session",
            tenant_id="default",
            method="static_api_key",
        )
        return None

    store = get_key_store()
    if store.has_keys():
        # ``store.verify`` runs a ~21ms scrypt derivation (in-memory store) or a
        # blocking DB read (Postgres store). This route is auth-exempt, so an
        # unauthenticated caller could otherwise stall the event loop on demand.
        api_key = await anyio.to_thread.run_sync(store.verify, raw_key)
        if api_key:
            _set_browser_session_cookie(
                response,
                request,
                subject=api_key.name,
                role=api_key.role.value,
                tenant_id=api_key.tenant_id,
                auth_method="browser_session",
                key_id=api_key.key_id,
                scopes=list(api_key.scopes),
            )
            log_action(
                "auth.browser_session_created",
                actor=api_key.name,
                resource="auth/session",
                tenant_id=api_key.tenant_id,
                method="api_key",
                key_id=api_key.key_id,
                role=api_key.role.value,
            )
            return None

    raise HTTPException(status_code=401, detail="Invalid API key")


@router.delete("/auth/session", tags=["enterprise"], status_code=204)
def delete_browser_session(request: Request, response: Response) -> Response:
    """Clear the same-origin browser session cookie."""
    from agent_bom.api.audit_log import log_action

    try:
        _clear_browser_session_cookie(response, request)
    except HTTPException as exc:
        if exc.status_code != 503:
            raise
        unavailable = JSONResponse(status_code=503, content={"detail": "Authentication state unavailable"})
        _delete_browser_session_cookies(unavailable, request)
        return unavailable
    tenant_id = getattr(request.state, "tenant_id", None) or "default"
    actor = getattr(request.state, "api_key_name", "") or "browser-session"
    log_action("auth.browser_session_cleared", actor=actor, resource="auth/session", tenant_id=tenant_id)
    response.status_code = 204
    return response


@router.post("/auth/keys", tags=["enterprise"], status_code=201)
def create_key(request: Request, req: CreateKeyRequest) -> dict:
    """Create a new API key. Returns the raw key once — store it securely."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import Role, create_api_key, get_key_store, resolve_scim_subject_binding, scopes_allow
    from agent_bom.rbac import role_rank

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or req.name

    try:
        role = Role(req.role)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid role: {req.role}. Must be admin, analyst, or viewer")

    caller_role_raw = str(getattr(request.state, "api_key_role", "admin") or "admin")
    try:
        caller_role = Role(caller_role_raw)
    except ValueError:
        raise HTTPException(status_code=403, detail="Caller role cannot delegate API keys")
    if role_rank(role) > role_rank(caller_role):
        raise HTTPException(status_code=403, detail="Cannot delegate an API key with a higher role than the caller")

    caller_scopes = list(getattr(request.state, "api_key_scopes", []) or [])
    if caller_scopes:
        if not req.scopes:
            raise HTTPException(status_code=403, detail="A scoped caller cannot create an unrestricted API key")
        if any(not scopes_allow(caller_scopes, child_scope) for child_scope in req.scopes):
            raise HTTPException(status_code=403, detail="Cannot delegate API key scopes outside the caller scope ceiling")

    try:
        raw_key, api_key = create_api_key(
            name=req.name,
            role=role,
            expires_at=req.expires_at,
            scopes=req.scopes,
            tenant_id=tenant_id,
            scim_subject_id=resolve_scim_subject_binding(request, req.scim_subject_id),
            owner=req.owner,
            principal_id=req.principal_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
    get_key_store().add(api_key)

    log_action(
        "auth.key_created",
        actor=actor,
        resource=f"key/{api_key.key_id}",
        role=req.role,
        tenant_id=tenant_id,
        expires_at=api_key.expires_at,
        rotation_policy="enforced",
    )

    return {
        "raw_key": raw_key,
        "key_id": api_key.key_id,
        "key_prefix": api_key.key_prefix,
        "name": api_key.name,
        "role": api_key.role.value,
        "tenant_id": api_key.tenant_id,
        "created_at": api_key.created_at,
        "expires_at": api_key.expires_at,
        "owner": api_key.owner,
        "principal_id": api_key.principal_id,
        "message": "Store the raw_key securely — it will not be shown again.",
    }


@router.post("/auth/keys/{key_id}/rotate", tags=["enterprise"], status_code=201)
def rotate_key(
    request: Request,
    key_id: str,
    req: RotateKeyRequest | None = None,
) -> dict:
    """Rotate an API key by minting a replacement and revoking the old key.

    Body is optional -- a rotation with no overrides accepts both `{}` and a
    completely missing body. All RotateKeyRequest fields default to None
    (inherit name from the current key, no expiry change, default overlap).
    """
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import create_api_key, get_api_key_policy, get_key_store, normalize_rotation_overlap_seconds

    if req is None:
        req = RotateKeyRequest()

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    store = get_key_store()
    current_key = store.get(key_id)
    if current_key is None or current_key.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail=f"Key {key_id} not found")

    overlap_seconds = normalize_rotation_overlap_seconds(req.overlap_seconds, policy=get_api_key_policy())
    overlap_until = (datetime.now(timezone.utc) + timedelta(seconds=overlap_seconds)).isoformat()

    replacement_name = req.name or current_key.name
    try:
        raw_key, replacement = create_api_key(
            name=replacement_name,
            role=current_key.role,
            expires_at=req.expires_at,
            scopes=list(current_key.scopes),
            tenant_id=current_key.tenant_id,
            scim_subject_id=current_key.scim_subject_id,
            owner=current_key.owner,
            principal_id=current_key.principal_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc

    store.add(replacement)
    if not store.mark_rotating(current_key.key_id, replacement_key_id=replacement.key_id, overlap_until=overlap_until):
        raise HTTPException(status_code=409, detail=f"Key {key_id} could not be marked for rotation")
    log_action(
        "auth.key_rotated",
        actor=actor,
        resource=f"key/{current_key.key_id}",
        tenant_id=tenant_id,
        replacement_key_id=replacement.key_id,
        previous_expires_at=current_key.expires_at,
        replacement_expires_at=replacement.expires_at,
        overlap_until=overlap_until,
        overlap_seconds=overlap_seconds,
    )

    return {
        "raw_key": raw_key,
        "key_id": replacement.key_id,
        "replaced_key_id": current_key.key_id,
        "key_prefix": replacement.key_prefix,
        "name": replacement.name,
        "role": replacement.role.value,
        "tenant_id": replacement.tenant_id,
        "created_at": replacement.created_at,
        "expires_at": replacement.expires_at,
        "overlap_until": overlap_until,
        "overlap_seconds": overlap_seconds,
        "message": (
            "Store the raw_key securely — it will not be shown again. The previous key remains valid until the overlap window ends."
        ),
    }


@router.get("/auth/keys", **documented(ApiKeysResponse), tags=["enterprise"])
def list_keys(request: Request) -> dict:
    """List all API keys (without hashes or raw values)."""
    from agent_bom.api.auth import get_key_store

    tenant_id = require_request_tenant_id(request)
    keys = get_key_store().list_keys(tenant_id=tenant_id)
    # schema_version on terminal list response.
    return {"schema_version": "v1", "keys": [k.to_dict() for k in keys]}
