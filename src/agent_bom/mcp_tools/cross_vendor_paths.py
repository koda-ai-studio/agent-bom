"""The cross-vendor attack-path queue for agents, served by the REST read behind it.

``/v1/graph/attack-paths/cross-vendor`` and this tool run the same function,
so pages, ordering, vendor-pair facets and generation pinning agree. Inputs
are checked here with the route's own bounds, since a direct call skips the
REST query validation.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable

from agent_bom.mcp_errors import CODE_VALIDATION_INVALID_ARGUMENT, mcp_error_json
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.mcp_tools.rest_parity import call_route

_VENDOR = re.compile(r"^[a-z0-9_.-]{0,64}$")
MAX_LIMIT = 1000


def _invalid(message: str, field: str) -> str:
    return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, message, details={"field": field})


async def cross_vendor_paths_impl(
    *,
    tenant_id: str = "default",
    scan_id: str | None = None,
    source_vendor: str | None = None,
    target_vendor: str | None = None,
    offset: int = 0,
    limit: int = 25,
    snapshot_generation: str | None = None,
    cursor: str | None = None,
    _truncate_response: Callable[[str], str] | None = None,
) -> str:
    """Paths whose source and target nodes are recorded in different vendors, in queue order, with pair facets."""
    for field, value in (("source_vendor", source_vendor), ("target_vendor", target_vendor)):
        if value is not None and not _VENDOR.match(value):
            return _invalid(f"{field} must be a lowercase recorded vendor id such as 'snowflake' or 'aws'", field)
    if not 1 <= limit <= MAX_LIMIT:
        return _invalid(f"limit must be between 1 and {MAX_LIMIT}", "limit")
    if offset < 0:
        return _invalid("offset must be non-negative", "offset")
    if snapshot_generation is not None and len(snapshot_generation) > 128:
        return _invalid("snapshot_generation is at most 128 characters", "snapshot_generation")
    if cursor is not None and len(cursor) > 1024:
        return _invalid("cursor is at most 1024 characters", "cursor")
    tenant_id = resolve_mcp_tool_tenant_id(tenant_id)
    body, error = await call_route(
        "get_cross_vendor_attack_paths",
        tenant_id=tenant_id,
        path="/v1/graph/attack-paths/cross-vendor",
        scan_id=scan_id,
        snapshot_generation=snapshot_generation,
        offset=offset,
        limit=limit,
        source_vendor=source_vendor or None,
        target_vendor=target_vendor or None,
        cursor=cursor or None,
    )
    if error:
        return error
    encoded = json.dumps(
        {"tool": "cross_vendor_paths", "tenant_id": tenant_id, "source": "v1_graph_attack_paths_cross_vendor", **body},
        separators=(",", ":"),
        default=str,
    )
    return _truncate_response(encoded) if _truncate_response is not None else encoded


__all__ = ["cross_vendor_paths_impl"]
