"""Read-only MCP transport for the canonical experimental consequence service."""

from __future__ import annotations

import asyncio
from typing import Annotated, Any

from pydantic import Field, ValidationError

from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.graph.consequence.contracts import ConsequenceRequest
from agent_bom.mcp_errors import (
    CODE_NOT_FOUND_RESOURCE,
    CODE_UNSUPPORTED_BACKEND,
    CODE_UPSTREAM_UNAVAILABLE,
    CODE_VALIDATION_INVALID_ARGUMENT,
    mcp_error_json,
)
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.mcp_tools.compromise import assessment_api
from agent_bom.mcp_tools.storage import default_graph_store


async def consequence_assessment_impl(
    *,
    request: ConsequenceRequest | dict,
    scan_id: str,
    snapshot_generation: str | None = None,
    tenant_id: str = "default",
    _get_graph_store=None,
) -> str:
    try:
        from fastapi import HTTPException

        request_model, assess_snapshot_consequences = assessment_api("consequence")
    except ImportError:
        return mcp_error_json(CODE_UNSUPPORTED_BACKEND, "Install agent-bom[api] for persisted graph assessments.")
    try:
        core = ConsequenceRequest.model_validate(request)
        body = request_model(**core.model_dump(), scan_id=scan_id, snapshot_generation=snapshot_generation)
    except ValidationError:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "Select an explicit assumption and valid bounded snapshot request.")
    tenant = resolve_mcp_tool_tenant_id(tenant_id)
    try:
        if _get_graph_store is None:
            _get_graph_store = default_graph_store
        async with adaptive_backpressure("graph"):
            result = await asyncio.to_thread(assess_snapshot_consequences, _get_graph_store(), body, tenant_id=tenant)
        return result.model_dump_json()
    except HTTPException as exc:
        code = {404: CODE_NOT_FOUND_RESOURCE, 501: CODE_UNSUPPORTED_BACKEND}.get(exc.status_code, CODE_VALIDATION_INVALID_ARGUMENT)
        return mcp_error_json(code, "Assessment unavailable; verify the snapshot and assumptions.", details={"status": exc.status_code})
    except BackpressureRejectedError:
        return mcp_error_json(CODE_UPSTREAM_UNAVAILABLE, "Graph assessment capacity is busy; retry later.")
    except Exception:  # broad-except: Optional storage backends must return a sanitized MCP transport error.
        return mcp_error_json(CODE_UPSTREAM_UNAVAILABLE, "Graph storage is temporarily unavailable.")


def register_consequence_tool(mcp: Any, *, read_only: Any, execute_tool_async: Any) -> None:
    @mcp.tool(annotations=read_only, title="Consequence Assessment")
    async def consequence_assessment(
        request: Annotated[
            ConsequenceRequest, Field(description="Explicit starting assumption, affected occurrence and traversal bounds.")
        ],
        scan_id: Annotated[str, Field(min_length=1, max_length=1024, description="Persisted snapshot from graph inventory.")],
        snapshot_generation: Annotated[
            str | None, Field(min_length=1, max_length=256, description="Require this previously returned evidence revision.")
        ] = None,
        tenant_id: Annotated[str, Field(description="Compatibility hint; the server-bound tenant remains authoritative.")] = "default",
    ) -> str:
        """Trace experimental consequences, exact blockers and missing prerequisites.

        Agent/principal mode requires explicit assumed control. Vulnerability mode
        requires a linked affected occurrence. Current access and observed effects
        are never inferred. Session/exploitability producers remain unqualified.
        """
        return await execute_tool_async(
            "consequence_assessment",
            consequence_assessment_impl,
            request=request,
            scan_id=scan_id,
            snapshot_generation=snapshot_generation,
            tenant_id=tenant_id,
        )
