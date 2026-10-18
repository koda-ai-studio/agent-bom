"""Project credential-reach assessments and their recorded topology paths.

Assessment edges identify findings; they are not credential-use observations.
Only exact node IDs join a finding to its agent and credential references.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from agent_bom.core.severity import SEVERITY_RANK
from agent_bom.graph.analysis import GraphAnalysisState
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.credential_reach import credential_routes
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.security import sanitize_text

_RULE = "AGENT_REACHES_PRIVILEGED"
# Rendering bound for path payloads only; finding evaluation is never capped.
MAX_PATHS = 10_000


def _agents_by_identity(graph: UnifiedGraph) -> dict[str, set[str]]:
    index: dict[str, set[str]] = {}
    for node in graph.nodes.values():
        if node.entity_type != EntityType.AGENT:
            continue
        for key in ("canonical_id", "stable_id"):
            value = node.attributes.get(key)
            if isinstance(value, str) and value:
                index.setdefault(value, set()).add(node.id)
    return index


def _rebind_owner(graph: UnifiedGraph, row: dict[str, Any], index: dict[str, set[str]]) -> str | None:
    """The agent a row names when its recorded graph id came from another scope.

    A pushed report keeps the scanner's ``agent:cfg-...`` ids while the control
    plane scopes the same agent by its source. The agent's canonical id is the
    join; an ambiguous match binds nothing.
    """
    owner = row.get("node_id")
    if isinstance(owner, str) and owner in graph.nodes:
        return owner
    raw_asset = row.get("asset")
    asset: dict[str, Any] = raw_asset if isinstance(raw_asset, dict) else {}
    matches = index.get(str(asset.get("identifier") or "")) or set()
    return next(iter(matches)) if len(matches) == 1 else None


def _rebind_reference(node_id: str, recorded_owner: Any, owner: str) -> str:
    """Move a credential id recorded under the scanner's agent key onto the resolved agent key."""
    if not isinstance(recorded_owner, str) or recorded_owner == owner:
        return node_id
    old_prefix = f"cred:server:{recorded_owner.removeprefix('agent:')}:"
    if node_id.startswith(old_prefix):
        return f"cred:server:{owner.removeprefix('agent:')}:{node_id[len(old_prefix) :]}"
    return node_id


def project_credential_findings(graph: UnifiedGraph, findings: Any) -> None:
    """Materialize report occurrences after topology evaluation, idempotently."""
    if not isinstance(findings, list):
        return
    index = _agents_by_identity(graph)
    bound: dict[int, str] = {}
    for row in findings:
        if isinstance(row, dict) and (resolved := _rebind_owner(graph, row, index)) is not None:
            bound[id(row)] = resolved
    owners = dict.fromkeys(bound.values())
    routes = credential_routes(graph, owners, analyzer="credential_finding_projection")
    for row in findings:
        if not isinstance(row, dict) or row.get("source") != "GRAPH_ANALYSIS" or row.get("finding_type") != "COMBINATION":
            continue
        evidence = row.get("evidence")
        if not isinstance(evidence, dict) or evidence.get("rule_id") != _RULE:
            continue
        fid, owner = row.get("id"), bound.get(id(row))
        if not isinstance(fid, str) or not fid or not isinstance(owner, str):
            continue
        agent = graph.nodes.get(owner)
        if agent is None or agent.entity_type != EntityType.AGENT:
            continue
        raw_ids = evidence.get("node_ids")
        if not isinstance(raw_ids, list):
            continue
        recorded = row.get("node_id")
        references = {_rebind_reference(nid, recorded, owner) for nid in raw_ids if isinstance(nid, str)}
        credentials = sorted(nid for nid in references if nid in routes.get(owner, {}))
        node_id = f"misconfig:graph_analysis:{fid}"
        severity = str(row.get("severity") or "unknown").lower()
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.MISCONFIGURATION,
                label=sanitize_text(str(row.get("title") or "Agent credential reach"), max_len=500),
                severity=severity,
                attributes={
                    "finding_id": fid,
                    "finding_type": "COMBINATION",
                    "finding_source": "GRAPH_ANALYSIS",
                    "rule_id": _RULE,
                    "owner_node_id": owner,
                    "credential_node_ids": credentials,
                    "finding_ids_by_asset": {owner: [fid]},
                    "assessment_basis": "graph_topology",
                    "runtime_reachability_verified": False,
                    "remediation": sanitize_text(str(row.get("remediation_guidance") or ""), max_len=2000),
                },
                data_sources=["graph-analysis"],
            )
        )
        receipt = {
            "source": "graph-analysis",
            "tier": "derived",
            "derived_via": _RULE,
            "basis": "graph_topology",
            "evidence_basis": "modeled",
            "rule_id": _RULE,
            "finding_id": fid,
            "owner_node_id": owner,
            "runtime_reachability_verified": False,
        }
        graph.add_edge(UnifiedEdge(source=owner, target=node_id, relationship=RelationshipType.VULNERABLE_TO, evidence=dict(receipt)))
        for credential in credentials:
            graph.add_edge(
                UnifiedEdge(source=credential, target=node_id, relationship=RelationshipType.VULNERABLE_TO, evidence=dict(receipt))
            )


def credential_finding_paths(graph: UnifiedGraph) -> list[AttackPath]:
    """One bounded topology path per credential, restricted to its finding owner.

    Never use the rule's relationship_path template as a receipt. Walk real,
    traversable edges, up to the evaluator's six-hop depth, then append the
    explicitly modeled assessment association.
    """
    paths: list[AttackPath] = []
    findings = [
        node
        for node in graph.nodes.values()
        if node.attributes.get("finding_source") == "GRAPH_ANALYSIS" and node.attributes.get("rule_id") == _RULE
    ]
    owners = dict.fromkeys(owner for node in findings if isinstance(owner := node.attributes.get("owner_node_id"), str))
    if not owners:
        credential_routes(graph, (), analyzer="credential_finding_paths")
        return paths
    by_owner = credential_routes(graph, owners, analyzer="credential_finding_paths")
    # A shared credential may anchor thousands of findings: index associations
    # once rather than rescanning that credential's fan-out for every owner.
    associations = {(e.source, e.target) for e in graph.edges if e.relationship == RelationshipType.VULNERABLE_TO}
    for node in findings:
        attrs = node.attributes
        owner = attrs.get("owner_node_id")
        if not isinstance(owner, str):
            continue
        for credential in attrs.get("credential_node_ids", []):
            if not isinstance(credential, str):
                continue
            if len(paths) >= MAX_PATHS:
                previous = graph.analysis_status["credential_finding_paths"]
                status = replace(
                    previous,
                    status=GraphAnalysisState.LIMITED,
                    reason_codes=tuple(sorted({*previous.reason_codes, "path_budget"})),
                )
                graph.analysis_status["credential_finding_paths"] = status
                for path in paths:
                    path.analysis = status.to_dict()
                return paths
            route = by_owner.get(owner, {}).get(credential)
            if route is None or (credential, node.id) not in associations:
                continue
            hops, rels = route
            paths.append(
                AttackPath(
                    source=owner,
                    target=node.id,
                    hops=hops + [node.id],
                    edges=rels + [RelationshipType.VULNERABLE_TO.value],
                    composite_risk=min(39.0, SEVERITY_RANK.get(node.severity, 0) * 20.0 * 0.35),
                    summary="Modeled credential-reach finding from recorded topology; successful use, effective permission, "
                    "and exploitation require separate evidence. The final hop links the credential to its assessment.",
                    credential_exposure=[graph.nodes[credential].label],
                    vuln_ids=[node.label],
                    finding_ids=[attrs["finding_id"]],
                    reachability="unknown",
                    reachability_basis=["structural_topology_only"],
                    analysis=graph.analysis_status["credential_finding_paths"].to_dict(),
                )
            )
    return paths
