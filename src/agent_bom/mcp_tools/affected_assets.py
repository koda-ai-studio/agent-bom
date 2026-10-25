"""MCP ``affected_assets``: which assets an advisory affects, exactly as the REST route answers.

With a control plane (tenant advisory store or stored scans) the tool runs the
``GET /v1/intel/advisories/{id}/affected`` read function for the MCP tenant, so
REST and MCP cannot drift. Standalone, it answers from the CLI-local advisory
file (or the local feed record) against the most recent saved scan.
"""

from __future__ import annotations

import json
from typing import Any

from agent_bom.db.operator_advisories import local_affected_answer
from agent_bom.mcp_errors import CODE_NOT_FOUND_RESOURCE, CODE_VALIDATION_INVALID_ARGUMENT, mcp_error_json
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.mcp_tools.rest_parity import api_reads, call_route
from agent_bom.scanners.advisory_affected import MAX_LIMIT, VERDICT_FILTERS, AffectedCursorError, page_answer

LOCAL_TENANT = "local"


def _invalid(message: str, argument: str) -> str:
    return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, message, details={"argument": argument})


def _validation_error(advisory_id: str, verdict: str, limit: int) -> str | None:
    if not advisory_id or len(advisory_id) > 96:
        return _invalid("advisory_id is required (at most 96 characters)", "advisory_id")
    if verdict not in VERDICT_FILTERS:
        return _invalid(f"verdict must be one of: {', '.join(VERDICT_FILTERS)}", "verdict")
    if isinstance(limit, bool) or not 1 <= limit <= MAX_LIMIT:
        return _invalid(f"limit must be between 1 and {MAX_LIMIT}", "limit")
    return None


def _control_plane(reads: Any, tenant_id: str) -> bool:
    return bool(reads is not None and (reads.operator_advisory_store_configured() or reads.has_completed_scans(tenant_id)))


def _local_page(advisory_id: str, verdict: str, limit: int, cursor: str | None) -> Any:
    answer = local_affected_answer(advisory_id)
    if answer is None:
        return mcp_error_json(CODE_NOT_FOUND_RESOURCE, "Advisory not found in local declarations or the local feed")
    try:
        return page_answer(answer, tenant_id=LOCAL_TENANT, verdict=verdict, limit=limit, cursor=cursor)
    except AffectedCursorError as exc:
        return _invalid(str(exc), "cursor")


async def affected_assets_impl(
    *, advisory_id: str, verdict: str = "all", limit: int = 50, cursor: str | None = None, _truncate_response=lambda value: value
) -> str:
    advisory = (advisory_id or "").strip()
    error = _validation_error(advisory, verdict, limit)
    if error:
        return error
    reads = api_reads()
    tenant_id = resolve_mcp_tool_tenant_id()
    if _control_plane(reads, tenant_id):
        body, failure = await call_route(
            "get_advisory_affected_assets",
            tenant_id=tenant_id,
            path=f"/v1/intel/advisories/{advisory}/affected",
            advisory_id=advisory,
            verdict=verdict,
            limit=limit,
            cursor=cursor,
        )
        return failure or _truncate_response(json.dumps(body))
    page = _local_page(advisory, verdict, limit, cursor)
    return page if isinstance(page, str) else _truncate_response(json.dumps(page))
