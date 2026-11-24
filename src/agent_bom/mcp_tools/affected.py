"""``am_i_affected``: the ``GET /v1/affected`` answer for an advisory or package, unchanged."""

from __future__ import annotations

import json
from collections.abc import Callable

from agent_bom.mcp_errors import CODE_VALIDATION_INVALID_ARGUMENT, mcp_error_json
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.mcp_tools.rest_parity import call_route


async def am_i_affected_impl(*, q: str, tenant_id: str = "default", _truncate_response: Callable[[str], str] | None = None) -> str:
    """Affected findings, exposure window and reach for one advisory id or package, as the REST read returns them."""
    if not 2 <= len(q.strip()) <= 256:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT, "q must be an advisory id or package of 2 to 256 characters", details={"argument": "q"}
        )
    tenant_id = resolve_mcp_tool_tenant_id(tenant_id)
    body, error = await call_route("get_affected", tenant_id=tenant_id, path="/v1/affected", q=q.strip())
    if error:
        return error
    encoded = json.dumps(
        {"schema_version": "v1", "tool": "am_i_affected", "source": "v1_affected", **body}, separators=(",", ":"), default=str
    )
    return _truncate_response(encoded) if _truncate_response is not None else encoded


__all__ = ["am_i_affected_impl"]
