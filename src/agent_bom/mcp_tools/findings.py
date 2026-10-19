"""``findings_query`` and ``finding_detail``: the findings queue for agents.

``findings_query`` is ``/v1/findings`` itself (same filters, sort, cursor and
totals) with a compact row projection; ``finding_detail`` adds the graph paths
that carry one finding and its triage state.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

from agent_bom.mcp_errors import CODE_NOT_FOUND_RESOURCE, CODE_VALIDATION_INVALID_ARGUMENT, CODE_VALIDATION_MISSING_REQUIRED, mcp_error_json
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.mcp_tools.exposure_queue import hydrate, project_paths, summary_path
from agent_bom.mcp_tools.finding_graph import load_snapshot_paths, project_finding, public_graph_block
from agent_bom.mcp_tools.rest_parity import api_reads, api_unavailable, call_route
from agent_bom.mcp_tools.storage import default_graph_store

RISK_SCALE = {"risk_score": "0-10", "effective_reach_score": "0-100"}
_SUMMARY_FIELDS = (
    "id",
    "title",
    "severity",
    "severity_source",
    "lane",
    "cve_id",
    "package",
    "risk_score",
    "effective_reach_score",
    "effective_reach_band",
    "is_kev",
    "graph_reachable",
    "graph_reachable_from",
    "graph_reachable_from_count",
    "status",
    "lifecycle_status",
    "finding_node_id",
    "owner",
    "sla_due_at",
    "last_seen",
)
_CHOICES = {
    "reachability": ("reachable", "unreachable", "unassessed"),
    "triage": ("not_affected", "affected", "under_investigation", "untriaged"),
    "sla": ("overdue", "due", "unassigned"),
    "fields": ("summary", "full"),
}
_TRIAGE_ROW_FIELDS = ("status", "lifecycle_status", "suppressed", "suppression_id", "vex_status", "vex_justification")


def summary_row(row: dict[str, Any]) -> dict[str, Any]:
    summary = {key: row[key] for key in _SUMMARY_FIELDS if row.get(key) is not None}
    asset = row.get("asset")
    if isinstance(asset, dict) and asset.get("name"):
        summary["asset"] = asset["name"]
    return summary


def _encode(payload: dict[str, Any], truncate: Callable[[str], str] | None) -> str:
    encoded = json.dumps(payload, separators=(",", ":"), default=str)
    return truncate(encoded) if truncate is not None else encoded


async def findings_query_impl(
    *,
    tenant_id: str = "default",
    lane: str | None = None,
    q: str | None = None,
    severity: str | None = None,
    scan_id: str | None = None,
    sort: str = "effective_reach",
    limit: int = 25,
    cursor: str | None = None,
    kev: bool | None = None,
    framework: str | None = None,
    control: str | None = None,
    reachability: str | None = None,
    triage: str | None = None,
    sla: str | None = None,
    status: str | None = None,
    window_days: int | None = None,
    fields: str = "summary",
    _truncate_response: Callable[[str], str] | None = None,
) -> str:
    """Page ``/v1/findings`` for the tool tenant with a compact projection."""
    if not 1 <= limit <= 200:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "limit must be between 1 and 200", details={"argument": "limit"})
    for name, value in (("reachability", reachability), ("triage", triage), ("sla", sla), ("fields", fields)):
        if value is not None and value not in _CHOICES[name]:
            return mcp_error_json(
                CODE_VALIDATION_INVALID_ARGUMENT, f"{name} must be one of: {', '.join(_CHOICES[name])}", details={"argument": name}
            )
    tenant_id = resolve_mcp_tool_tenant_id(tenant_id)
    optional = {
        "lane": lane,
        "q": q,
        "severity": severity,
        "scan_id": scan_id,
        "cursor": cursor,
        "kev": kev,
        "framework": framework,
        "control": control,
        "reachability": reachability,
        "triage": triage,
        "sla": sla,
        "status": status,
        "window_days": window_days,
    }
    params = {key: value for key, value in optional.items() if value is not None}
    body, error = await call_route("list_findings", tenant_id=tenant_id, path="/v1/findings", sort=sort, limit=limit, **params)
    if error:
        return error
    rows = list(body.get("findings") or [])
    return _encode(
        {
            "schema_version": "v1",
            "tool": "findings_query",
            "tenant_id": tenant_id,
            "source": "v1_findings",
            "fields": fields,
            "total": body.get("total"),
            "count": len(rows),
            "has_more": body.get("has_more"),
            "next_cursor": body.get("next_cursor") or None,
            "sort": body.get("sort"),
            "filters": body.get("filters"),
            "window": body.get("window"),
            "count_metadata": body.get("count_metadata"),
            "warnings": body.get("warnings") or [],
            "risk_scale": RISK_SCALE,
            "findings": [summary_row(row) for row in rows] if fields == "summary" else rows,
        },
        _truncate_response,
    )


def _triage_block(reads: Any, tenant_id: str, row: dict[str, Any]) -> dict[str, Any]:
    block: dict[str, Any] = {key: row.get(key) for key in _TRIAGE_ROW_FIELDS if key in row}
    block["triage_state"] = reads.triage_state(tenant_id, row)
    return block


async def _graph_paths(
    graph: dict[str, Any], snapshot: dict[str, Any], *, tenant_id: str, path_limit: int, store: Any
) -> list[dict[str, Any]]:
    """Summaries of the first ``path_limit`` paths carrying the finding, ranked as the queue ranks them."""
    shown = (graph.get("matched") or [])[:path_limit]
    if not shown:
        return []
    rank_of = {id(path): index + 1 for index, path in enumerate(snapshot["paths"])}
    nodes, edges = await hydrate(store, tenant_id, snapshot["scan_id"], shown)
    projected = project_paths(
        shown, nodes=nodes, edges=edges, first_rank=1, scan_id=snapshot["scan_id"], ranks=[rank_of[id(path)] for path in shown]
    )
    return [summary_path(path) for path in projected]


async def finding_detail_impl(
    *,
    finding_id: str,
    tenant_id: str = "default",
    scan_id: str | None = None,
    path_limit: int = 5,
    _get_graph_store: Callable[[], Any] | None = None,
    _truncate_response: Callable[[str], str] | None = None,
) -> str:
    """One finding row plus the graph paths that carry it and its triage state."""
    if not finding_id.strip():
        return mcp_error_json(CODE_VALIDATION_MISSING_REQUIRED, "finding_id is required", details={"argument": "finding_id"})
    if len(finding_id) > 256 or "\x00" in finding_id:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "finding_id is not a valid identifier", details={"argument": "finding_id"})
    if not 1 <= path_limit <= 25:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "path_limit must be between 1 and 25", details={"argument": "path_limit"})
    tenant_id = resolve_mcp_tool_tenant_id(tenant_id)
    reads = api_reads()
    if reads is None:
        return api_unavailable()
    row = await asyncio.to_thread(reads.persisted_finding, tenant_id, finding_id, scan_id)
    if row is None:
        return mcp_error_json(CODE_NOT_FOUND_RESOURCE, "Finding not found for this tenant", details={"finding_id": finding_id})
    get_store = _get_graph_store or default_graph_store
    snapshot = await load_snapshot_paths(tenant_id=tenant_id, scan_id=None, get_store=get_store)
    graph = project_finding(row, snapshot)
    paths = (
        await _graph_paths(graph, snapshot, tenant_id=tenant_id, path_limit=path_limit, store=get_store()) if graph.get("matched") else []
    )
    triage = await asyncio.to_thread(_triage_block, reads, tenant_id, row)
    return _encode(
        {
            "schema_version": "v1",
            "tool": "finding_detail",
            "tenant_id": tenant_id,
            "risk_scale": {**RISK_SCALE, "graph.paths[].riskScore": "0-100"},
            "finding": row,
            "graph": {**public_graph_block(graph), "paths": paths},
            "triage": triage,
        },
        _truncate_response,
    )


__all__ = ["RISK_SCALE", "finding_detail_impl", "findings_query_impl", "summary_row"]
