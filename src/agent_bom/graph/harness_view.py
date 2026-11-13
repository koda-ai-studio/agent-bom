"""Read view of agent harnesses from a persisted graph snapshot.

Placements are derived from the stored framework-agent nodes and their
declared ``delegated_to`` / ``shares_server`` edges with
:func:`agent_bom.graph.harness_model.derive_placements`, the same function the
graph build stamps on each node, so the API and MCP answer what the graph says.
The security overlay reads what the graph already holds for each agent: its
severity and risk score, the findings it is ``vulnerable_to``, and counts of its
other outgoing edges. Nothing is inferred beyond those records.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from typing import Any

from agent_bom.core.severity import SEVERITY_RANK
from agent_bom.graph.harness_model import HARNESS_MODEL_VERSION, HarnessEdge, HarnessPlacement, derive_placements

FRAMEWORK_AGENT = "framework-agent"
STRUCTURAL_RELATIONSHIPS = frozenset({"delegated_to", "shares_server"})
# Edges that describe the harness itself, not what an agent reaches.
_NOT_REACH = STRUCTURAL_RELATIONSHIPS | {"uses_framework", "serves_model", "contains", "vulnerable_to"}
MAX_AGENTS_PER_HARNESS = 500
MAX_FLOW_EDGES_PER_HARNESS = 2_000
MAX_LIST_ITEMS = 50
MODELLED_FRAMEWORKS = ("langgraph", "crewai")
COVERAGE_GAPS = (
    "CrewAI manager_agent, tasks and process order are not modelled as delegation; crews show their declared members only.",
    "AutoGen speaker selection and OpenAI Agents SDK handoffs are not modelled yet.",
    "Model references are listed only where the source passes a literal model name or a module-level binding to one.",
    "Edges are declared from source code; observed runtime paths are not compared here.",
)


def _value(raw: Any) -> str:
    return str(getattr(raw, "value", raw) or "")


def _edge_evidence(edge: Any) -> dict[str, Any]:
    evidence = getattr(edge, "evidence", None)
    return evidence if isinstance(evidence, dict) else {}


def _branches(evidence: dict[str, Any]) -> tuple[str, ...]:
    raw = evidence.get("branches") or ([evidence["branch"]] if evidence.get("branch") else [])
    return tuple(str(item) for item in raw if str(item))


def harness_edges(edges: Iterable[Any], agent_ids: set[str]) -> list[HarnessEdge]:
    """Declared structural edges between framework agents, as the model reads them."""
    out: list[HarnessEdge] = []
    for edge in edges:
        relationship = _value(edge.relationship)
        if relationship not in STRUCTURAL_RELATIONSHIPS or edge.source not in agent_ids or edge.target not in agent_ids:
            continue
        evidence = _edge_evidence(edge)
        out.append(
            HarnessEdge(
                source=edge.source,
                target=edge.target,
                relationship=relationship,
                evidence=str(evidence.get("evidence") or ""),
                kind=str(evidence.get("kind") or ""),
                branches=_branches(evidence),
            )
        )
    return out


def place_agents(agent_nodes: list[Any], edges: list[HarnessEdge]) -> dict[str, HarnessPlacement]:
    participants = {edge.source for edge in edges} | {edge.target for edge in edges}
    declared = {node.id: str(node.attributes.get("parent_id") or "") for node in agent_nodes if node.id in participants}
    return derive_placements(declared, edges)


def harness_order(placements: dict[str, HarnessPlacement], nodes_by_id: dict[str, Any]) -> list[str]:
    """Harness root ids in a stable order: label, then id."""
    roots = {placement.harness_id for placement in placements.values()}
    return sorted(roots, key=lambda root: (str(getattr(nodes_by_id.get(root), "label", "")).lower(), root))


def _names(items: Any) -> list[str]:
    names = [str(item.get("name") if isinstance(item, dict) else item) for item in items or []]
    return [name for name in dict.fromkeys(names) if name][:MAX_LIST_ITEMS]


def _construct(root: Any, edges: list[HarnessEdge]) -> str:
    outgoing = [edge.evidence for edge in edges if edge.source == root.id]
    for prefix, construct in (
        ("Crew(", "Crew"),
        ("GroupChat(", "GroupChat"),
        ("create_supervisor(", "supervisor"),
        ("create_swarm(", "swarm"),
    ):
        if any(evidence.startswith(prefix) for evidence in outgoing):
            return construct
    if any(str(cap.get("name") if isinstance(cap, dict) else cap) == "state-graph" for cap in root.attributes.get("capabilities") or []):
        return "StateGraph"
    return "agent"


def _agent_row(node: Any, placement: HarnessPlacement) -> dict[str, Any]:
    attrs = node.attributes
    return {
        "id": node.id,
        "label": node.label,
        "framework": str(attrs.get("framework") or ""),
        "role": placement.role,
        "layer": placement.layer,
        "entry": placement.entry,
        "parent_id": placement.parent_id,
        "file_path": str(attrs.get("file_path") or ""),
        "line_number": int(attrs.get("line_number") or 0),
        "model_refs": _names(attrs.get("model_refs")),
        "tools": [name for name in _names(attrs.get("capabilities")) if name != "state-graph"],
        "credential_refs": _names(attrs.get("credential_refs")),
        "dynamic_edges": bool(attrs.get("dynamic_edges")),
    }


def _unresolved(node: Any) -> list[dict[str, Any]]:
    attrs = node.attributes
    routes = [route for route in attrs.get("unresolved_routes") or [] if isinstance(route, dict)]
    if not routes:  # snapshots written before routes were kept verbatim carry only their reasons
        routes = [{"evidence": "", "line_number": 0, "reason": reason} for reason in attrs.get("unresolved_route_reasons") or []]
    return [
        {
            "agent_id": node.id,
            "status": "unresolved",
            "evidence": str(route.get("evidence") or ""),
            "line_number": int(route.get("line_number") or 0),
            "reason": str(route.get("reason") or ""),
        }
        for route in routes
    ]


def _flow_row(edge: HarnessEdge, raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": edge.source,
        "target": edge.target,
        "relationship": edge.relationship,
        "kind": edge.flow,
        "conditional": edge.conditional,
        "branches": list(edge.branches),
        "evidence": edge.evidence,
        "provenance": str(raw.get("provenance") or "declared"),
        "confidence": str(raw.get("confidence") or ""),
        "file_path": str(raw.get("file_path") or ""),
        "line_number": int(raw.get("line_number") or 0),
    }


def build_harness(
    root_id: str,
    placements: dict[str, HarnessPlacement],
    nodes_by_id: dict[str, Any],
    edges: list[HarnessEdge],
    raw_evidence: dict[tuple[str, str, str], dict[str, Any]],
) -> dict[str, Any]:
    """One harness: its layers, flow edges and unresolved routes (no overlay yet)."""
    members = sorted(
        (agent_id for agent_id, placement in placements.items() if placement.harness_id == root_id),
        key=lambda agent_id: (placements[agent_id].layer, str(nodes_by_id[agent_id].label).lower(), agent_id),
    )
    kept = members[:MAX_AGENTS_PER_HARNESS]
    kept_ids = set(kept)
    flow = [edge for edge in edges if edge.source in kept_ids and edge.target in kept_ids]
    layers: dict[int, list[dict[str, Any]]] = {}
    for agent_id in kept:
        layers.setdefault(placements[agent_id].layer, []).append(_agent_row(nodes_by_id[agent_id], placements[agent_id]))
    unresolved = [route for agent_id in kept for route in _unresolved(nodes_by_id[agent_id])]
    root = nodes_by_id[root_id]
    models = sorted({ref for rows in layers.values() for row in rows for ref in row["model_refs"]})
    return {
        "harness_id": root_id,
        "label": root.label,
        "framework": str(root.attributes.get("framework") or ""),
        "harness_kind": _construct(root, edges),
        "file_path": str(root.attributes.get("file_path") or ""),
        "line_number": int(root.attributes.get("line_number") or 0),
        "agent_count": len(members),
        "layer_count": len(layers),
        "entry_agent_ids": [agent_id for agent_id in kept if placements[agent_id].entry],
        "orchestrator_ids": [agent_id for agent_id in kept if placements[agent_id].role == "orchestrator"],
        "models": models,
        "layers": [{"layer": layer, "agents": layers[layer]} for layer in sorted(layers)],
        "flow_edges": [
            _flow_row(edge, raw_evidence.get((edge.source, edge.target, edge.relationship), {}))
            for edge in flow[:MAX_FLOW_EDGES_PER_HARNESS]
        ],
        "unresolved_route_count": len(unresolved),
        "unresolved_routes": unresolved[:MAX_AGENTS_PER_HARNESS],
        "truncated": {"agents": len(members) > len(kept), "flow_edges": len(flow) > MAX_FLOW_EDGES_PER_HARNESS},
    }


def overlay_inputs(edges: Iterable[Any]) -> tuple[dict[str, Counter[str]], dict[str, set[str]], dict[str, str]]:
    """Per agent: outgoing reach counts by relationship, findings it is vulnerable to; per root: its declaring project."""
    reach: dict[str, Counter[str]] = {}
    findings: dict[str, set[str]] = {}
    declared_in: dict[str, str] = {}
    for edge in edges:
        relationship = _value(edge.relationship)
        if relationship == "contains":
            declared_in.setdefault(edge.target, edge.source)
        elif relationship == "vulnerable_to":
            findings.setdefault(edge.source, set()).add(edge.target)
        elif relationship not in _NOT_REACH:
            reach.setdefault(edge.source, Counter())[relationship] += 1
    return reach, findings, declared_in


def _max_severity(values: Iterable[str]) -> str:
    ranked = [value.lower() for value in values if SEVERITY_RANK.get(value.lower(), 0) > 0]
    return max(ranked, key=lambda value: SEVERITY_RANK[value]) if ranked else ""


def apply_overlay(
    harness: dict[str, Any],
    nodes_by_id: dict[str, Any],
    reach: dict[str, Counter[str]],
    findings: dict[str, set[str]],
    declared_in: dict[str, str],
    finding_nodes: dict[str, Any],
) -> dict[str, Any]:
    """Attach each agent's recorded severity, findings and reach, and the harness rollup."""
    severities: list[str] = []
    risk = 0.0
    with_findings = 0
    finding_ids: set[str] = set()
    credentials: set[str] = set()
    for layer in harness["layers"]:
        for row in layer["agents"]:
            node = nodes_by_id[row["id"]]
            own = findings.get(row["id"], set())
            finding_severity = _max_severity(str(getattr(finding_nodes.get(fid), "severity", "") or "") for fid in own)
            row["security"] = {
                "severity": str(node.severity or ""),
                "risk_score": float(node.risk_score or 0.0),
                "findings": len(own),
                "max_finding_severity": finding_severity,
                "reach": dict(sorted(reach.get(row["id"], Counter()).items())),
            }
            severities.extend([str(node.severity or ""), finding_severity])
            risk = max(risk, float(node.risk_score or 0.0))
            with_findings += bool(own)
            finding_ids |= own
            credentials.update(row["credential_refs"])
    project = nodes_by_id.get(declared_in.get(harness["harness_id"], ""))
    harness["declared_in"] = (
        {"id": project.id, "label": project.label, "severity": str(project.severity or ""), "risk_score": float(project.risk_score or 0.0)}
        if project is not None
        else None
    )
    harness["security"] = {
        "max_severity": _max_severity(severities),
        "max_risk_score": risk,
        "agents_with_findings": with_findings,
        "findings": len(finding_ids),
        "credential_refs": sorted(credentials)[:MAX_LIST_ITEMS],
    }
    return harness


def empty_summary() -> dict[str, Any]:
    return {"harnesses": 0, "framework_agents": 0, "placed_agents": 0, "unplaced_framework_agents": 0, "frameworks": {}}


def summary(agent_nodes: list[Any], placements: dict[str, HarnessPlacement], harness_total: int) -> dict[str, Any]:
    frameworks = Counter(str(node.attributes.get("framework") or "unknown") for node in agent_nodes if node.id in placements)
    return {
        "harnesses": harness_total,
        "framework_agents": len(agent_nodes),
        "placed_agents": len(placements),
        "unplaced_framework_agents": len(agent_nodes) - len(placements),
        "frameworks": dict(sorted(frameworks.items())),
    }


def coverage(*, complete: bool, agent_cap: int) -> dict[str, Any]:
    return {
        "model": HARNESS_MODEL_VERSION,
        "provenance": "declared",
        "frameworks_modelled": list(MODELLED_FRAMEWORKS),
        "gaps": list(COVERAGE_GAPS),
        "complete": complete,
        "framework_agent_cap": agent_cap,
    }


__all__ = [
    "FRAMEWORK_AGENT",
    "MAX_AGENTS_PER_HARNESS",
    "STRUCTURAL_RELATIONSHIPS",
    "apply_overlay",
    "build_harness",
    "coverage",
    "empty_summary",
    "harness_edges",
    "harness_order",
    "overlay_inputs",
    "place_agents",
    "summary",
]
