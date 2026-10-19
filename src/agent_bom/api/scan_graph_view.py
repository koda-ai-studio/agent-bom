"""Scan graph view."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from fastapi.responses import PlainTextResponse

from agent_bom.api.models import ScanJob


async def _scan_graph_compute_call(fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
    """Run graph rendering/derivation for scan subresources off the event loop."""
    return await asyncio.to_thread(fn, *args, **kwargs)


def _effective_reach_lookup(job: ScanJob) -> dict[str, dict[str, Any]]:
    """Build a per-occurrence lookup of agent/tool/credential reach context.

    Keyed by finding identity (``canonical_id`` / ``finding_id``), never by
    CVE id: unrelated occurrences share CVE ids, and only an occurrence the
    context graph links to an agent may carry agent, tool or credential reach.
    """
    result = job.result or {}
    blast = result.get("blast_radius", []) or result.get("blast_radii", []) or []
    try:
        from agent_bom.context_graph import build_context_graph
        from agent_bom.effective_reach import occurrence_contexts

        graph = build_context_graph(result.get("agents", []) or [], blast)
        return occurrence_contexts(graph, blast)
    except Exception:  # pragma: no cover - never break the findings list
        return {}


def _attach_unified_graph_view(payload: dict[str, Any], result: dict[str, Any], *, scan_id: str, tenant_id: str) -> dict[str, Any]:
    """Attach the canonical graph view without changing legacy context fields."""
    try:
        from agent_bom.graph.builder import build_unified_graph_from_report

        unified = build_unified_graph_from_report(result, scan_id=scan_id, tenant_id=tenant_id)
    except Exception:  # pragma: no cover - graph bridge must not break legacy response
        payload.setdefault("warnings", []).append("Unified graph view unavailable for this scan result")
        return payload

    payload["unified_graph"] = {
        "schema_version": "agent-bom.graph/v1",
        **unified.to_dict(),
    }
    return payload


def _context_graph_payload(result: dict[str, Any], *, agent: str | None, scan_id: str, tenant_id: str) -> dict[str, Any]:
    from agent_bom.context_graph import (
        NodeKind,
        build_context_graph,
        collect_lateral_paths,
        compute_interaction_risks,
        to_serializable,
    )

    graph = build_context_graph(
        result.get("agents", []),
        result.get("blast_radius", []),
    )
    paths: list = []
    paths_truncated = False
    if agent:
        node_id = f"agent:{agent}"
        if node_id in graph.nodes:
            paths, paths_truncated = collect_lateral_paths(graph, [node_id])
    else:
        source_ids = (nid for nid, node in sorted(graph.nodes.items()) if node.kind == NodeKind.AGENT)
        paths, paths_truncated = collect_lateral_paths(graph, source_ids)
    risks = compute_interaction_risks(graph)

    payload = to_serializable(graph, paths, risks)
    payload["stats"]["lateral_paths_truncated"] = paths_truncated
    attached = _attach_unified_graph_view(payload, result, scan_id=scan_id, tenant_id=tenant_id)
    from agent_bom.output.interop_security import sanitize_linked_document

    return sanitize_linked_document(attached)


def _graph_export_response(
    result: dict[str, Any], *, format: str, mermaid_limit: int, scan_id: str | None = None, tenant_id: str | None = None
) -> dict | str | PlainTextResponse:
    from agent_bom.output.graph_export import (
        build_graph_from_scan_data,
        to_cypher,
        to_dot,
        to_graphml,
        to_mermaid,
    )
    from agent_bom.output.graph_export import (
        to_json as graph_to_json,
    )

    graph = build_graph_from_scan_data(result)

    def _render_mermaid(g: Any) -> PlainTextResponse:
        if mermaid_limit == 0:
            return PlainTextResponse(
                to_mermaid(g, max_nodes=None, max_edges=None),
                media_type="text/plain",
            )
        return PlainTextResponse(
            to_mermaid(g, max_nodes=mermaid_limit),
            media_type="text/plain",
        )

    formats = {
        "dot": lambda g: PlainTextResponse(to_dot(g), media_type="text/vnd.graphviz"),
        "mermaid": _render_mermaid,
        "graphml": lambda g: PlainTextResponse(to_graphml(g), media_type="application/xml"),
        "cypher": lambda g: PlainTextResponse(to_cypher(g), media_type="text/plain"),
    }
    if format in formats:
        return formats[format](graph)
    return graph_to_json(graph, scan_id=scan_id, tenant_id=tenant_id)
