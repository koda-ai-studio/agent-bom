"""Tenant helpers for authenticated API request handlers."""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable

from fastapi import HTTPException, Request
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from agent_bom.api.dashboard_not_found import non_api_not_found
from agent_bom.api.request_tenant import require_request_tenant_id as require_request_tenant_id
from agent_bom.api.route_policy import route_policy
from agent_bom.platform_invariants import normalize_tenant_id


async def call_with_request_tenant(
    request: Request, call_next: RequestResponseEndpoint, *, authenticate: Callable[..., Awaitable[Response]] | None = None
) -> Response:
    """Reject incomplete identity before dispatch and restore database context."""
    try:
        tenant_id = require_request_tenant_id(request)
    except HTTPException:
        return JSONResponse(status_code=500, content={"detail": "Authenticated tenant context is unavailable"})
    if route_policy(request.method, request.url.path) is None:
        not_found = non_api_not_found(request.method, request.url.path)
        if not_found is not None:
            return not_found
        return JSONResponse(status_code=403, content={"detail": "Forbidden — operation has no authorization policy"})
    request.state.tenant_id = tenant_id
    if authenticate is not None:
        from agent_bom.api.stream_authorization import bind_http_stream_authorization

        bind_http_stream_authorization(request, authenticate)
    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        return await call_next(request)

    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    token = set_current_tenant(tenant_id)
    try:
        return await call_next(request)
    finally:
        reset_current_tenant(token)


# Legacy SDK bodies carry the schema default rather than a real tenant. Treat it
# as "unset" so an untouched client field is not read as a cross-tenant request.
_UNSET_BODY_TENANTS = frozenset({"", "default"})


def require_body_tenant_match(body_tenant_id: object, request_tenant_id: str) -> None:
    """Fail closed when a write body names a tenant the caller is not authenticated for.

    Eight write routes accept a ``tenant_id`` in the request body for legacy SDK
    compatibility. None of them ever routed the write to it — the authenticated
    tenant has always been authoritative — but they disagreed on the answer:
    three returned 403, three ignored it and appended a response warning, two
    ignored it silently. A caller asking to write into another tenant gets one
    answer everywhere, and it is the fail-closed one.

    Passing the caller's own tenant (or leaving the field at its schema default)
    stays valid, so conforming clients are unaffected.
    """
    if body_tenant_id is None:
        return
    candidate = str(body_tenant_id).strip()
    if candidate in _UNSET_BODY_TENANTS:
        return
    if normalize_tenant_id(candidate) == request_tenant_id:
        return
    raise HTTPException(
        status_code=403,
        detail="Forbidden — tenant_id in the request body must match the authenticated tenant",
    )
