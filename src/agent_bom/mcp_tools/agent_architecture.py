"""Multi-agent harness architecture for agents, served by the REST read behind it.

``/v1/graph/agent-architecture`` and this tool run the same route function, so
harnesses, layers, flow edges, the security overlay and generation pinning
agree. Inputs are checked here with the route's own bounds, since a direct
call skips the REST query validation.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from agent_bom.mcp_errors import CODE_VALIDATION_INVALID_ARGUMENT, mcp_error_json
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.mcp_tools.rest_parity import call_route

MAX_LIMIT = 50
MAX_OFFSET = 100_000


def _invalid(message: str, field: str) -> str:
    return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, message, details={"field": field})


def _validate(scan_id: str | None, offset: int, limit: int, snapshot_generation: str | None, cursor: str | None) -> str | None:
    checks = (
        (not 1 <= limit <= MAX_LIMIT, f"limit must be between 1 and {MAX_LIMIT}", "limit"),
        (not 0 <= offset <= MAX_OFFSET, f"offset must be between 0 and {MAX_OFFSET}", "offset"),
        (scan_id is not None and len(scan_id) > 256, "scan_id is at most 256 characters", "scan_id"),
        (
            snapshot_generation is not None and len(snapshot_generation) > 128,
            "snapshot_generation is at most 128 characters",
            "snapshot_generation",
        ),
        (cursor is not None and len(cursor) > 1024, "cursor is at most 1024 characters", "cursor"),
    )
    return next((_invalid(message, field) for failed, message, field in checks if failed), None)


async def agent_architecture_impl(
    *,
    tenant_id: str = "default",
    scan_id: str | None = None,
    offset: int = 0,
    limit: int = 20,
    snapshot_generation: str | None = None,
    cursor: str | None = None,
    _truncate_response: Callable[[str], str] | None = None,
) -> str:
    """Harnesses declared in the snapshot: layers, flow edges, unresolved routes and the security overlay."""
    error = _validate(scan_id, offset, limit, snapshot_generation, cursor)
    if error:
        return error
    tenant_id = resolve_mcp_tool_tenant_id(tenant_id)
    params: dict[str, Any] = {
        "scan_id": scan_id or None,
        "snapshot_generation": snapshot_generation,
        "offset": offset,
        "limit": limit,
        "cursor": cursor or None,
    }
    body, failure = await call_route("get_agent_architecture", tenant_id=tenant_id, path="/v1/graph/agent-architecture", **params)
    if failure:
        return failure
    encoded = json.dumps(
        {"tool": "agent_architecture", "source": "v1_graph_agent_architecture", **body},
        separators=(",", ":"),
        default=str,
    )
    return _truncate_response(encoded) if _truncate_response is not None else encoded


__all__ = ["agent_architecture_impl"]
