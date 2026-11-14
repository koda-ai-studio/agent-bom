"""Eval suites and safety-eval coverage findings on the unified graph.

Each detected suite becomes an ``eval_suite`` node with ``evaluates`` edges to
the agents and models its files target. A framework agent folded into the
project agent is represented by that host node, so the edge and the coverage
finding attach there instead of inventing a second agent node. The coverage
finding node is drawn here (same id the report row carries) so the generic
finding-row pass finds it already attached.
"""

from __future__ import annotations

from typing import Any

from agent_bom.evidence.finding_node_ids import finding_row_node_id
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import edge_evidence
from agent_bom.graph.finding_row_projection import _edge_for, _new_node, _row_times
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.training_projection import _model_node_id
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.security import sanitize_text

_COLLECTOR = "eval-scan"
_MAX_SUITES_PER_AGENT = 50


def eval_suite_node_id(stable_id: str) -> str:
    return f"eval_suite:{stable_id}"


def _agent_node(graph: UnifiedGraph, agent_id: str, host_id: str | None) -> UnifiedNode | None:
    node = graph.nodes.get(agent_id)
    if node is not None and node.entity_type == EntityType.AGENT:
        return node
    host = graph.nodes.get(host_id) if host_id else None
    return host if host is not None and host.entity_type == EntityType.AGENT else None


def _suite_summary(suite: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": eval_suite_node_id(str(suite.get("stable_id") or "")),
        "harness": suite.get("harness", ""),
        "name": sanitize_text(str(suite.get("name") or ""), max_len=200),
        "purpose": suite.get("purpose", "unknown"),
        "file_path": suite.get("file_path", ""),
        "link_status": suite.get("link_status", ""),
        "results": list(suite.get("results") or [])[:5],
    }


def _empty_coverage(status: str) -> dict[str, Any]:
    return {"assessed": status == "complete", "status": status, "safety_suites": 0, "suites": []}


def _init_coverage(graph: UnifiedGraph, ai_inventory: dict[str, Any], host_id: str | None) -> None:
    """Every framework agent (and the project agent holding folded ones) records whether evals were searched."""
    coverage = ai_inventory.get("eval_coverage")
    if not isinstance(coverage, dict):
        return
    status = str(coverage.get("status") or "partial")
    for node in graph.nodes_by_type(EntityType.AGENT):
        if node.attributes.get("agent_type") == "framework-agent" or node.id == host_id:
            node.attributes["eval_coverage"] = _empty_coverage(status)


def _record_coverage(node: UnifiedNode, suite: dict[str, Any] | None) -> None:
    coverage = node.attributes.get("eval_coverage")
    if not isinstance(coverage, dict):
        coverage = _empty_coverage("complete")
        node.attributes["eval_coverage"] = coverage
    if suite is None:
        return
    summary = _suite_summary(suite)
    if any(existing["id"] == summary["id"] for existing in coverage["suites"]):
        return
    if len(coverage["suites"]) < _MAX_SUITES_PER_AGENT:
        coverage["suites"].append(summary)
    coverage["safety_suites"] += summary["purpose"] == "safety"


def _project_suite(graph: UnifiedGraph, suite: dict[str, Any], data_source: str, host_id: str | None) -> None:
    stable = str(suite.get("stable_id") or "").strip()
    if not stable:
        return
    node_id = eval_suite_node_id(stable)
    graph.add_node(
        UnifiedNode(
            id=node_id,
            entity_type=EntityType.EVAL_SUITE,
            label=sanitize_text(str(suite.get("name") or stable), max_len=200),
            attributes={
                "harness": suite.get("harness", ""),
                "purpose": suite.get("purpose", "unknown"),
                "purpose_evidence": list(suite.get("purpose_evidence") or []),
                "file_path": suite.get("file_path", ""),
                "line_number": suite.get("line_number", 0),
                "link_status": suite.get("link_status", ""),
                "targets": list(suite.get("targets") or []),
                "results": list(suite.get("results") or []),
                "scope": suite.get("scope", ""),
                "executed": False,
            },
            dimensions=NodeDimensions(surface=str(suite.get("harness") or "")),
            data_sources=[data_source, _COLLECTOR],
        )
    )
    targets: set[str] = set()
    for agent_id in suite.get("linked_agent_ids") or []:
        agent = _agent_node(graph, str(agent_id), host_id)
        if agent is not None:
            targets.add(agent.id)
            _record_coverage(agent, suite)
    for model_ref in suite.get("linked_models") or []:
        model_id = _model_node_id(str(model_ref))
        graph.add_node(
            UnifiedNode(
                id=model_id,
                entity_type=EntityType.MODEL,
                label=str(model_ref),
                attributes={"model_ref": str(model_ref), "source": _COLLECTOR},
                dimensions=NodeDimensions(surface="model"),
                data_sources=[data_source, _COLLECTOR],
            )
        )
        targets.add(model_id)
    for target in sorted(targets):
        graph.add_edge(
            UnifiedEdge(
                source=node_id,
                target=target,
                relationship=RelationshipType.EVALUATES,
                evidence=edge_evidence(
                    _COLLECTOR,
                    "static_scan",
                    "eval_target",
                    harness=suite.get("harness", ""),
                    purpose=suite.get("purpose", "unknown"),
                    file_path=suite.get("file_path", ""),
                ),
            )
        )


def _project_finding(graph: UnifiedGraph, row: dict[str, Any], host_id: str | None) -> None:
    node_id = finding_row_node_id(row)
    raw_evidence = row.get("evidence")
    evidence: dict[str, Any] = raw_evidence if isinstance(raw_evidence, dict) else {}
    agent = _agent_node(graph, str(evidence.get("agent_id") or ""), host_id)
    if node_id is None or agent is None:
        return
    if node_id not in graph.nodes:
        graph.add_node(_new_node(row, node_id, _COLLECTOR))
    finding = graph.nodes[node_id]
    edge = _edge_for(finding, agent)
    if edge is None:
        return
    source, target, relationship = edge
    graph.add_edge(
        UnifiedEdge(
            source=source,
            target=target,
            relationship=relationship,
            evidence=edge_evidence(_COLLECTOR, "static_scan", "finding_row", finding_id=row.get("id")),
            **_row_times(row),
        )
    )
    _record_coverage(agent, None)


def project_eval_suites(
    graph: UnifiedGraph,
    ai_inventory: Any,
    findings: Any,
    data_source: str,
    *,
    host_agent_id: str | None = None,
) -> None:
    """Add eval-suite nodes, their ``evaluates`` edges and the coverage findings' agent edges."""
    if not isinstance(ai_inventory, dict):
        return
    _init_coverage(graph, ai_inventory, host_agent_id)
    for suite in ai_inventory.get("eval_suites") or []:
        if isinstance(suite, dict):
            _project_suite(graph, suite, data_source, host_agent_id)
    for row in findings if isinstance(findings, list) else []:
        if isinstance(row, dict) and row.get("finding_type") == "EVAL_COVERAGE_GAP" and row.get("id"):
            _project_finding(graph, row, host_agent_id)
