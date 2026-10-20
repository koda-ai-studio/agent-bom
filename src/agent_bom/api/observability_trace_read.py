"""Tenant trace ingestion, content screening and trace exploration."""

from __future__ import annotations

import asyncio
from typing import Any

from agent_bom.api.hub_ingest import ingest_runtime_findings
from agent_bom.api.models import JobStatus
from agent_bom.api.observability_costs import _persist_llm_costs
from agent_bom.api.observability_events import _logger, _now, _persist_runtime_observations
from agent_bom.api.runtime_event_store import get_runtime_event_store
from agent_bom.api.stores import _get_analytics_store, _get_graph_store, _get_store
from agent_bom.api.trace_collection.trace_evidence import record_otlp_evidence, vulnerable_inventory
from agent_bom.api.trace_explorer_read import assemble_trace_explorer
from agent_bom.core.experimental import disabled_message, is_enabled


def _screen_content_enabled(explicit: bool | None) -> bool:
    """Resolve whether opt-in trace-content screening runs for this request.

    Off by default and preserves the metadata-only privacy posture: content is
    only screened when the request explicitly opts in, or the deployment set the
    ``AGENT_BOM_TRACE_CONTENT_SCREENING`` default.
    """
    if explicit is not None:
        return bool(explicit)
    from agent_bom.config import trace_content_screening_enabled

    return trace_content_screening_enabled()


def _screen_trace_content_events(body: dict, *, tenant_id: str) -> list[dict[str, Any]]:
    """Run Shield over trace content (opt-in) and return redacted finding events.

    Raw content is screened in-memory and never stored — only the redacted
    detector/severity/summary per span is returned/persisted.
    """
    from agent_bom.trace_content import screen_trace_content

    try:
        findings = screen_trace_content(body)
    except Exception:  # noqa: BLE001 — screening never blocks metadata ingest
        _logger.warning("Trace content screening skipped", exc_info=False)
        return []
    events: list[dict[str, Any]] = []
    for finding in findings:
        events.append(
            {
                "event_id": f"{finding.trace_id}:{finding.span_id}:{finding.detector}",
                "event_timestamp": _now(),
                "event_type": "trace_content_finding",
                "detector": f"shield_{finding.detector}",
                "severity": finding.severity,
                "tool_name": finding.tool_name,
                "message": finding.message,
                "session_id": finding.trace_id,
                "trace_id": finding.trace_id,
                "span_id": finding.span_id,
                "source_id": "otel_content",
            }
        )
    if events:
        try:
            _get_analytics_store().record_events(events, tenant_id=tenant_id)
        except Exception:  # noqa: BLE001
            _logger.warning("Trace content analytics sync skipped", exc_info=False)
        _persist_runtime_observations(events, tenant_id=tenant_id, source="otel_content")
    return events


def _ingest_traces_sync(body: dict, tenant_id: str, screen: bool) -> dict:
    from agent_bom.otel_ingest import flag_vulnerable_tool_calls, parse_otel_traces

    # GenAI cost spans are independent of tool-call traces — price them first
    # so spend is captured even for payloads with no adk.tool.* spans.
    llm_cost = _persist_llm_costs(body, tenant_id=tenant_id)

    # Opt-in, privacy-safe content screening (off by default).
    content_findings: list[dict[str, Any]] = []
    if screen:
        content_findings = _screen_trace_content_events(body, tenant_id=tenant_id)

    traces = parse_otel_traces(body)
    flagged = flag_vulnerable_tool_calls(traces, *vulnerable_inventory(_get_store().list_all(tenant_id=tenant_id))) if traces else []
    evidence: Any = (
        record_otlp_evidence(body, tenant_id=tenant_id, flagged=flagged, content_findings=content_findings, sink=ingest_runtime_findings)
        if is_enabled("traces")
        else {"recorded": False, "reason": disabled_message("traces")}
    )
    if not traces:
        return {
            "traces": 0,
            "flagged": [],
            "llm_calls": llm_cost["calls"],
            "llm_cost_usd": llm_cost["cost_usd"],
            "content_findings": content_findings,
            "content_screened": screen,
            "normalized": evidence,
            "message": "No tool call traces found",
        }

    return {
        "traces": len(traces),
        "persisted_events": 0,
        "llm_calls": llm_cost["calls"],
        "llm_cost_usd": llm_cost["cost_usd"],
        "content_findings": content_findings,
        "content_screened": screen,
        "normalized": evidence,
        "flagged": [
            {
                "tool_name": f.trace.tool_name,
                "server": f.server or f.trace.server_name,
                "package_name": f.package_name or f.trace.package_name,
                "cve_ids": f.matched_cves,
                "correlation_basis": f.correlation_basis,
                "reason": f.reason,
                "severity": f.severity,
                "span_id": f.trace.span_id,
            }
            for f in flagged
        ],
    }


def _blast_radius_views_for_tenant(tenant_id: str) -> list[Any]:
    """Adapt persisted scan blast-radius dicts into objects the correlation reads."""
    from types import SimpleNamespace

    views: list[Any] = []
    for job in _get_store().list_all(tenant_id=tenant_id):
        if job.status != JobStatus.DONE or not job.result:
            continue
        for br in job.result.get("blast_radius", []) or []:
            if not isinstance(br, dict):
                continue
            pkg_spec = str(br.get("package", "") or "")
            pkg_name = pkg_spec.split("@", 1)[0] if pkg_spec else ""
            servers = [s if isinstance(s, str) else str(s.get("name", "")) for s in br.get("affected_servers", []) or []]
            agents = [a if isinstance(a, str) else str(a.get("name", "")) for a in br.get("affected_agents", []) or []]
            tools = [t if isinstance(t, str) else str(t.get("name", "")) for t in br.get("exposed_tools", []) or []]
            vuln = SimpleNamespace(
                id=str(br.get("vulnerability_id", "") or ""),
                severity=str(br.get("severity", "unknown") or "unknown"),
                cvss_score=br.get("cvss_score"),
                epss_score=br.get("epss_score"),
                is_kev=bool(br.get("is_kev", False)),
            )
            views.append(
                SimpleNamespace(
                    vulnerability=vuln,
                    package=SimpleNamespace(name=pkg_name),
                    affected_servers=servers,
                    affected_agents=agents,
                    exposed_tools=tools,
                    exposed_credentials=[str(c) for c in br.get("exposed_credentials", []) or []],
                    risk_score=float(br.get("risk_score", 0.0) or 0.0),
                )
            )
    return views


def _nhi_by_credential_for_tenant(tenant_id: str) -> dict[str, list[dict[str, Any]]]:
    """Best-effort map of exposed credential name -> the NHIs that hold it.

    Reads the tenant's unified graph: for each managed-identity node, the
    credential nodes it reaches (1-2 hops) index that identity. Never raises —
    returns an empty map when no graph/identity data is available.
    """
    out: dict[str, list[dict[str, Any]]] = {}
    try:
        from agent_bom.api.stores import _get_graph_store
        from agent_bom.graph.nhi_governance import evaluate_identity_governance
        from agent_bom.graph.types import EntityType

        graph = _get_graph_store().load_graph(tenant_id=tenant_id)
        identities = [n for n in graph.nodes.values() if n.entity_type == EntityType.MANAGED_IDENTITY]
        if not identities:
            return out
        verdicts = {v.node_id: v.to_dict() for v in evaluate_identity_governance(graph)}
        for node in identities[:5000]:
            verdict = verdicts.get(node.id, {"node_id": node.id, "name": str(node.attributes.get("name") or node.id)})
            # Walk up to 2 hops for reachable credential nodes.
            frontier = [node.id]
            seen: set[str] = set()
            for _hop in range(2):
                next_frontier: list[str] = []
                for nid in frontier:
                    for edge in graph.edges_from(nid):
                        target = graph.nodes.get(edge.target)
                        if target is None or edge.target in seen:
                            continue
                        seen.add(edge.target)
                        if target.entity_type == EntityType.CREDENTIAL:
                            cred_name = str(target.attributes.get("name") or target.attributes.get("env_var") or target.id)
                            out.setdefault(cred_name.lower(), []).append(verdict)
                        else:
                            next_frontier.append(edge.target)
                frontier = next_frontier
    except Exception:  # noqa: BLE001
        _logger.warning("NHI credential resolution skipped", exc_info=False)
        return out
    return out


def _build_trace_explorer_payload_sync(
    tenant_id: str, *, limit: int = 100, scan_id: str | None = None, offset: int = 0, **filters: Any
) -> dict[str, object]:
    """Assemble trace evidence off the event loop, bounded by the request limit."""
    from agent_bom.api import cost_store, scan_finding_projection, scan_finding_read
    from agent_bom.api.routes import gateway_feed

    feed = gateway_feed.build_gateway_feed(
        tenant_id=tenant_id,
        alerts=gateway_feed._load_tenant_alerts(tenant_id),
        llm_records=list(cost_store.get_cost_store().list_records(tenant_id, limit=limit)),
        limit=limit,
    )
    findings = (
        finding
        for job in scan_finding_read._completed_jobs_for_tenant(tenant_id)
        for finding in scan_finding_projection._iter_scan_findings(job)
    )
    return assemble_trace_explorer(
        get_runtime_event_store(),
        tenant_id,
        limit=limit,
        scan_id=scan_id,
        feed=feed,
        finding_rows=findings,
        graph_store=_get_graph_store() if scan_id else None,
        offset=offset,
        **filters,
    )


async def _trace_explorer_payload_for_tenant(tenant_id: str, *, limit: int = 100) -> dict[str, object]:
    """Shared trace explorer builder for runtime surfaces (offloaded off-loop)."""
    bounded_limit = max(1, min(limit, 200))
    return await asyncio.to_thread(_build_trace_explorer_payload_sync, tenant_id, limit=bounded_limit)
