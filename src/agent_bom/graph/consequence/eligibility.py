"""Reuse recorded authorization classification with path-scoped restrictions."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime

from agent_bom.graph.compromise import CompromiseRequest, _actions, _instant
from agent_bom.graph.consequence.contracts import Consequence, ConsequenceRequest, SessionBinding, Status
from agent_bom.graph.consequence.projection import project_action
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge


def actions_for_path(
    graph: UnifiedGraph,
    edge: UnifiedEdge,
    request: ConsequenceRequest,
    at: datetime,
    node_ids: tuple[str, ...],
    edge_ids: tuple[str, ...],
    sessions: tuple[SessionBinding, ...],
    partial: bool,
) -> tuple[list[Consequence], bool]:
    # Native collector receipts carry their own observation time. The direct
    # classifier independently checks every timestamp against the same clock.
    # Do not fill missing/stale correlation freshness or overwrite explicit gaps.
    evidence = dict(edge.evidence)
    if evidence.get("source") == "authorization-evidence" and "freshness" not in evidence and not edge.provenance.get("correlation"):
        evidence["freshness"] = "fresh"
    inspected = replace(edge, evidence=evidence)
    options = CompromiseRequest(root_node_id=edge.source, assume_control=True, max_evidence_age_seconds=request.max_evidence_age_seconds)
    actions, limited, _ = _actions(_receipt_scope(graph, inspected), inspected, options, at)
    result = []
    for action in actions:
        reasons = list(action.reason_codes)
        status: Status = "unknown"
        if action.permission == "supported_at_collection":
            status = "supported"
        elif action.permission == "denied_at_collection":
            status = "blocked"
        if partial:
            status = "unknown"
            reasons.append("partial_graph_evidence")
        if sessions and action.action and action.resource:
            if any(
                not any(scope.action == action.action and scope.resource == action.resource for scope in session.scope)
                for session in sessions
            ):
                status = "blocked"
                reasons.append("outside_session_scope")
        # Sessions and permission observations must describe the same time window.
        observed = _instant(action.observed_at)
        if sessions and (observed is None or any((stamp := _instant(s.observed_at)) is None or observed < stamp for s in sessions)):
            status = "unknown"
            reasons.append("permission_precedes_session_evidence")
        result.append(
            project_action(
                action,
                node_ids=[*node_ids, edge.target],
                edge_ids=[*edge_ids, edge.id],
                session_ids=[s.session_id for s in sessions],
                evidence_refs=[s.evidence_ref for s in sessions],
                status=status,
                reasons=reasons,
            )
        )
    return result, limited


def _receipt_scope(graph: UnifiedGraph, edge: UnifiedEdge) -> UnifiedGraph:
    """Reuse the native producer's exact node binding without a client alias join."""
    rows = edge.evidence.get("authorization_decisions")
    if not isinstance(rows, list) or not rows:
        return graph
    source = graph.nodes[edge.source]
    mapped = [
        r
        for r in rows
        if isinstance(r, dict)
        and r.get("principal_node_id") == edge.source
        and r.get("target_node_id") == edge.target
        and r.get("provider") == source.attributes.get("cloud_provider")
        and isinstance(r.get("principal_id"), str)
    ]
    principals = {r["principal_id"] for r in mapped}
    if len(mapped) != len(rows) or len(principals) != 1:
        return graph
    scoped = UnifiedGraph(scan_id=graph.scan_id, tenant_id=graph.tenant_id, created_at=graph.created_at)
    scoped.add_node(replace(source, attributes={**source.attributes, "principal_id": next(iter(principals))}))
    target = graph.nodes.get(edge.target)
    if target is not None:
        scoped.add_node(target)
    return scoped
