"""Read middleware-established tenant identity without importing route policy."""

from fastapi import HTTPException, Request

from agent_bom.core.tenancy import require_explicit_tenant_id


def require_request_tenant_id(request: Request) -> str:
    """Return the middleware-established tenant id for an API request.

    Route handlers should not silently invent the default tenant. The API
    middleware owns that fallback so a missing request tenant fails closed
    instead of crossing into the single-tenant bucket by accident.
    """
    try:
        return require_explicit_tenant_id(getattr(request.state, "tenant_id", None))
    except ValueError as exc:
        raise HTTPException(status_code=500, detail="Authenticated tenant context is unavailable") from exc
