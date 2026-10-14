"""``graph_diff``: what changed between two graph snapshots, answered by ``/v1/graph/diff``."""

from __future__ import annotations

import json
from collections.abc import Callable

from agent_bom.mcp_errors import CODE_VALIDATION_INVALID_ARGUMENT, mcp_error_json
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.mcp_tools.rest_parity import call_route

GRAPH_DIFF_VIEWS = ("summary", "detail")


def _invalid(message: str, argument: str) -> str:
    return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, message, details={"argument": argument})


async def graph_diff_impl(
    *,
    tenant_id: str = "default",
    from_scan_id: str | None = None,
    to_scan_id: str | None = None,
    view: str = "summary",
    change: str | None = None,
    kind: str | None = None,
    entity_type: str | None = None,
    relationship: str | None = None,
    node_id: str | None = None,
    limit: int = 50,
    cursor: str | None = None,
    _truncate_response: Callable[[str], str] | None = None,
) -> str:
    """The REST graph diff for the tool tenant: a summary, or a filtered detail page."""
    if view not in GRAPH_DIFF_VIEWS:
        return _invalid("view must be summary or detail", "view")
    if not 1 <= limit <= 200:
        return _invalid("limit must be between 1 and 200", "limit")
    if bool(from_scan_id) != bool(to_scan_id):
        return _invalid("Pass both from_scan_id and to_scan_id, or neither to compare the latest two snapshots.", "from_scan_id")
    tenant_id = resolve_mcp_tool_tenant_id(tenant_id)
    body, error = await call_route(
        "graph_diff_read",
        tenant_id=tenant_id,
        path="/v1/graph/diff",
        old=from_scan_id,
        new=to_scan_id,
        view=view,
        change=change,
        kind=kind,
        entity_type=entity_type,
        relationship=relationship,
        node_id=node_id,
        limit=limit,
        cursor=cursor,
    )
    if error:
        return error
    payload = {"tool": "graph_diff", "tenant_id": tenant_id, "source": "v1_graph_diff", **body}
    encoded = json.dumps(payload, separators=(",", ":"), default=str)
    return _truncate_response(encoded) if _truncate_response is not None else encoded


__all__ = ["GRAPH_DIFF_VIEWS", "graph_diff_impl"]
