"""Answer an MCP tool with the exact read function behind a REST route.

The tool's tenant comes from ``resolve_mcp_tool_tenant_id``; it is placed on a
synthetic request exactly where the API's auth middleware places the caller's
tenant, so the route reads the same rows, filters and paging. The API is
reached only through :mod:`agent_bom.api.mcp_reads`, loaded when a tool runs;
without the API extra the tool says so instead of guessing.
"""

from __future__ import annotations

from typing import Any

from agent_bom.mcp_errors import (
    CODE_CONFLICT_STATE,
    CODE_INTERNAL_UNEXPECTED,
    CODE_NOT_FOUND_RESOURCE,
    CODE_UNSUPPORTED_BACKEND,
    CODE_UPSTREAM_UNAVAILABLE,
    CODE_VALIDATION_INVALID_ARGUMENT,
    mcp_error_json,
)
from agent_bom.mcp_tools.estate_refusal import retryable_estate_refusal

API_EXTRA_REQUIRED = "This tool reads the control-plane API's persisted evidence; install agent-bom[api] to enable it."


def api_reads() -> Any:
    """The API read facade, or ``None`` in an install without the API extra."""
    try:
        from agent_bom.api import mcp_reads
    except ImportError:
        return None
    return mcp_reads


def api_unavailable() -> str:
    return mcp_error_json(CODE_UNSUPPORTED_BACKEND, API_EXTRA_REQUIRED)


def tenant_request(tenant_id: str, path: str, query: dict[str, Any] | None = None) -> Any:
    from urllib.parse import urlencode

    from starlette.requests import Request

    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "root_path": "",
            "query_string": urlencode({key: value for key, value in (query or {}).items() if value is not None}).encode(),
            "headers": [],
            "client": ("mcp", 0),
            "server": ("mcp", 0),
            "state": {"tenant_id": tenant_id, "auth_method": "mcp"},
        }
    )


def _error_for_status(exc: Any) -> str:
    refusal = retryable_estate_refusal(exc)
    if refusal is not None:
        return refusal
    status, detail = exc.status_code, exc.detail
    message = detail if isinstance(detail, str) else "The request was rejected."
    if status == 404:
        return mcp_error_json(CODE_NOT_FOUND_RESOURCE, message)
    if status == 409:
        return mcp_error_json(CODE_CONFLICT_STATE, message)
    if status in {429, 503}:
        return mcp_error_json(CODE_UPSTREAM_UNAVAILABLE, "The control plane is busy; retry the request.")
    if 400 <= status < 500:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, message)
    return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "An internal error has occurred.")


async def call_route(route_name: str, *, tenant_id: str, path: str, **params: Any) -> tuple[Any, str | None]:
    """``(body, None)`` from the named REST read, or ``(None, mcp_error_json)``."""
    reads = api_reads()
    if reads is None:
        return None, api_unavailable()
    try:
        return await reads.call_read(route_name, tenant_request(tenant_id, path, params), **params), None
    except reads.HTTPException as exc:
        return None, _error_for_status(exc)


__all__ = ["API_EXTRA_REQUIRED", "api_reads", "api_unavailable", "call_route", "tenant_request"]
