"""``executive_brief``: the leadership read ``GET /v1/brief`` serves, for agents."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from agent_bom.mcp_errors import CODE_VALIDATION_INVALID_ARGUMENT, mcp_error_json
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.mcp_tools.estate_refusal import seeding_refusal
from agent_bom.mcp_tools.rest_parity import call_route

MAX_LIMIT = 25


async def executive_brief_impl(
    *,
    tenant_id: str = "default",
    limit: int = 5,
    _truncate_response: Callable[[str], str] | None = None,
) -> str:
    """Return the same object as ``GET /v1/brief`` under the caller's authenticated tenant."""
    if not 1 <= limit <= MAX_LIMIT:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, f"limit must be between 1 and {MAX_LIMIT}", details={"argument": "limit"})
    tenant = resolve_mcp_tool_tenant_id(tenant_id)
    refusal = seeding_refusal(tenant)
    if refusal is not None:
        return refusal
    body, error = await call_route("get_executive_brief", tenant_id=tenant, path="/v1/brief", limit=limit)
    if error is not None:
        return error
    payload: dict[str, Any] = {"tool": "executive_brief", **body}
    encoded = json.dumps(payload, indent=2, default=str)
    return _truncate_response(encoded) if _truncate_response is not None else encoded


__all__ = ["MAX_LIMIT", "executive_brief_impl"]
