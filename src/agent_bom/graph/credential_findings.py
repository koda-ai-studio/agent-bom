"""Project credential-reach assessments and their recorded topology paths.

Assessment edges identify findings; they are not credential-use observations.
Only exact node IDs join a finding to its agent and credential references.
"""

from __future__ import annotations

from collections import deque
from typing import Any

from agent_bom.core.severity import SEVERITY_RANK
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.security import sanitize_text

_RULE = "AGENT_REACHES_PRIVILEGED"
_CREDENTIAL_TYPES = {EntityType.CREDENTIAL, EntityType.CREDENTIAL_REF}


def project_credential_findings(graph: UnifiedGraph, findings: Any) -> None:
    """Materialize report occurrences after topology evaluation, idempotently."""
    if not isinstance(findings, list):
        return
    for row in findings:
        if not isinstance(row, dict) or row.get("source") != "GRAPH_ANALYSIS" or row.get("finding_type") != "COMBINATION":
            continue
        evidence = row.get("evidence")
        if not isinstance(evidence, dict) or evidence.get("rule_id") != _RULE:
            continue
        fid, owner = row.get("id"), row.get("node_id")
        if not isinstance(fid, str) or not fid or not isinstance(owner, str):
            continue
        agent = graph.nodes.get(owner)
        if agent is None or agent.entity_type != EntityType.AGENT:
            continue
        raw_ids = evidence.get("node_ids")
        if not isinstance(raw_ids, list):
            continue
        credentials = sorted(
            {nid for nid in raw_ids if isinstance(nid, str) and nid in graph.nodes and graph.nodes[nid].entity_type in _CREDENTIAL_TYPES}
        )
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
            "basis": "graph_topology",
            "evidence_basis": "modeled",
            "rule_id": _RULE,
            "finding_id": fid,
            "owner_node_id": owner,
            "runtime_reachability_verified": False,
        }
        graph.add_edge(UnifiedEdge(source=owner, target=node_id, relationship=RelationshipType.VULNERABLE_TO, evidence=dict(receipt)))
        for credential in credentials:
            graph.add_edge(UnifiedEdge(source=credential, target=node_id, relationship=RelationshipType.TRIGGERS, evidence=dict(receipt)))


def credential_finding_paths(graph: UnifiedGraph) -> list[AttackPath]:
    """One bounded topology path per credential, restricted to its finding owner.

    Never use the rule's relationship_path template as a receipt. Walk real,
    traversable edges, up to the evaluator's six-hop depth, then append the
    explicitly modeled assessment association.
    """
    paths = []
    by_owner: dict[str, dict[str, tuple[list[str], list[str]]]] = {}
    for node in graph.nodes.values():
        attrs = node.attributes
        if attrs.get("finding_source") != "GRAPH_ANALYSIS" or attrs.get("rule_id") != _RULE:
            continue
        owner = attrs.get("owner_node_id")
        if not isinstance(owner, str) or owner not in graph.nodes:
            continue
        if owner not in by_owner:
            reached: dict[str, tuple[list[str], list[str]]] = {owner: ([owner], [])}
            queue = deque([owner])
            while queue and len(reached) < 5000:
                current = queue.popleft()
                hops, rels = reached[current]
                if len(rels) >= 6:
                    continue
                for edge in graph.adjacency.get(current, []):
                    if not edge.traversable or edge.target in reached or edge.target not in graph.nodes:
                        continue
                    if graph.nodes[edge.target].entity_type == EntityType.MISCONFIGURATION:
                        continue
                    reached[edge.target] = (hops + [edge.target], rels + [edge.relationship.value])
                    queue.append(edge.target)
                    if len(reached) >= 5000:
                        break
            by_owner[owner] = reached
        for credential in attrs.get("credential_node_ids", []):
            route = by_owner[owner].get(credential)
            if route is None or not any(
                e.target == node.id and e.relationship == RelationshipType.TRIGGERS for e in graph.adjacency.get(credential, [])
            ):
                continue
            hops, rels = route
            paths.append(
                AttackPath(
                    source=owner,
                    target=node.id,
                    hops=hops + [node.id],
                    edges=rels + [RelationshipType.TRIGGERS.value],
                    composite_risk=min(39.0, SEVERITY_RANK.get(node.severity, 0) * 20.0 * 0.35),
                    summary="Modeled credential-reach finding from recorded topology; successful use, effective permission, "
                    "and exploitation require separate evidence. The final hop links the credential to its assessment.",
                    credential_exposure=[graph.nodes[credential].label],
                    vuln_ids=[node.label],
                    finding_ids=[attrs["finding_id"]],
                    reachability="unknown",
                    reachability_basis=["structural_topology_only"],
                )
            )
    return paths
