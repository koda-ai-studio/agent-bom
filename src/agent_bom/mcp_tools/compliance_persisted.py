"""``compliance`` tool: the tenant's persisted posture first, a laptop scan only on request.

With completed scans in the control plane the tool returns exactly
``/v1/compliance/summary`` (and ``/v1/compliance/{framework}``), plus the
findings that drive a control from ``/v1/findings?framework=&control=``. A
local MCP-configuration scan runs only when asked for, or when the process has
no persisted evidence at all, and is labelled with its narrower scope.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

from agent_bom.mcp_errors import CODE_NOT_FOUND_RESOURCE, CODE_VALIDATION_INVALID_ARGUMENT, mcp_error_json
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.mcp_tools.compliance import compliance_impl
from agent_bom.mcp_tools.rest_parity import api_reads, call_route

SOURCES = ("auto", "persisted", "local_scan")


def _has_persisted_evidence(tenant_id: str) -> bool:
    reads = api_reads()
    return reads is not None and bool(reads.has_completed_scans(tenant_id))


def _encode(payload: dict[str, Any], truncate: Callable[[str], str] | None) -> str:
    encoded = json.dumps(payload, separators=(",", ":"), default=str)
    return truncate(encoded) if truncate is not None else encoded


async def _persisted(
    tenant_id: str, framework: str | None, control: str | None, limit: int, cursor: str | None
) -> tuple[dict[str, Any] | None, str | None]:
    summary, error = await call_route("get_compliance_summary", tenant_id=tenant_id, path="/v1/compliance/summary")
    if error:
        return None, error
    payload: dict[str, Any] = {
        "source": "persisted_tenant_compliance",
        "scope": {
            "tenant_id": tenant_id,
            "scan_id": None,
            "scan_count": summary.get("scan_count"),
            "latest_scan": summary.get("latest_scan"),
            "basis": "every completed scan job in the tenant control plane, as /v1/compliance/summary",
        },
        "summary": summary,
    }
    if framework:
        detail, error = await call_route(
            "get_compliance_by_framework", tenant_id=tenant_id, path=f"/v1/compliance/{framework}", framework=framework
        )
        if error:
            return None, error
        payload["framework"] = detail
    if control:
        params: dict[str, Any] = {"framework": framework, "control": control, "limit": limit}
        if cursor:
            params["cursor"] = cursor
        rows, error = await call_route("list_findings", tenant_id=tenant_id, path="/v1/findings", **params)
        if error:
            return None, error
        payload["driving_findings"] = {
            "source": "v1_findings",
            "framework": framework,
            "control": control,
            "ids": [row.get("id") for row in rows.get("findings") or []],
            "total": rows.get("total"),
            "has_more": rows.get("has_more"),
            "next_cursor": rows.get("next_cursor") or None,
            "window": rows.get("window"),
        }
    return payload, None


async def compliance_tool_impl(
    *,
    tenant_id: str = "default",
    source: str = "auto",
    framework: str | None = None,
    control: str | None = None,
    limit: int = 50,
    cursor: str | None = None,
    config_path: str | None = None,
    image: str | None = None,
    _run_scan_pipeline: Any,
    _truncate_response: Callable[[str], str] | None = None,
) -> str:
    """Return persisted tenant compliance, or a labelled local scan when asked or when none exists."""
    if source not in SOURCES:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT, f"source must be one of: {', '.join(SOURCES)}", details={"argument": "source"}
        )
    if control and not framework:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "control requires framework", details={"argument": "control"})
    if not 1 <= limit <= 500:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "limit must be between 1 and 500", details={"argument": "limit"})
    tenant_id = resolve_mcp_tool_tenant_id(tenant_id)
    if source != "local_scan":
        if await asyncio.to_thread(_has_persisted_evidence, tenant_id):
            payload, error = await _persisted(tenant_id, framework, control, limit, cursor)
            return error if error else _encode(payload or {}, _truncate_response)
        if source == "persisted":
            return mcp_error_json(
                CODE_NOT_FOUND_RESOURCE,
                "No persisted compliance evidence for this tenant; run a scan into the control plane or pass source='local_scan'.",
                details={"tenant_id": tenant_id},
            )

    raw = await compliance_impl(
        config_path=config_path, image=image, _run_scan_pipeline=_run_scan_pipeline, _truncate_response=lambda value: value
    )
    result = json.loads(raw)
    if isinstance(result, dict) and "error" in result:
        return raw
    # Keep the local result's top-level shape for existing consumers; add its scope label.
    result.update(
        source="local_scan",
        scope={"tenant_id": None, "scan_id": None, "basis": "MCP client configurations visible to this MCP server process"},
        reason="requested" if source == "local_scan" else "no_persisted_tenant_evidence",
    )
    return _encode(result, _truncate_response)


__all__ = ["SOURCES", "compliance_tool_impl"]
