"""Project recorded MCP audit findings onto exact inventory identities."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.security import sanitize_text


def project_mcp_audit_findings(graph: UnifiedGraph, findings: Any) -> None:
    """Use canonical IDs only; an unlinked observation stays unlinked."""
    if not isinstance(findings, list):
        return
    rows = [row for row in findings if _is_audit_finding(row)]
    if not rows:
        return
    identities: dict[str, set[str]] = defaultdict(set)
    for node in graph.nodes.values():
        if node.entity_type in {EntityType.TOOL, EntityType.SERVER}:
            for key in ("canonical_id", "stable_id"):
                value = node.attributes.get(key)
                if isinstance(value, str) and value:
                    identities[value].add(node.id)
    for row in rows:
        evidence = row.get("evidence") or {}
        asset = row.get("asset") or {}
        if not isinstance(evidence, dict) or not isinstance(asset, dict):
            continue
        finding_id = row.get("id")
        if not isinstance(finding_id, str) or not finding_id:
            continue
        targets = _asset_targets(identities, asset, evidence)
        if not targets:
            continue
        node_id = f"misconfig:mcp_audit:{finding_id}"
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.MISCONFIGURATION,
                label=sanitize_text(str(row.get("title") or "MCP audit finding"), max_len=500),
                severity=str(row.get("severity") or "medium").lower(),
                attributes={
                    "finding_id": finding_id,
                    "finding_source": "MCP_SCAN",
                    "assessment_basis": evidence.get("assessment_basis") or evidence.get("basis") or "descriptor_heuristic",
                    "runtime_reachability_verified": False,
                },
                data_sources=["mcp-audit"],
            )
        )
        for target in sorted(targets):
            graph.add_edge(
                UnifiedEdge(
                    source=target,
                    target=node_id,
                    relationship=RelationshipType.VULNERABLE_TO,
                    evidence={"source": "mcp-audit", "basis": "configuration", "runtime_reachability_verified": False},
                )
            )


def _is_audit_finding(row: Any) -> bool:
    if not isinstance(row, dict) or row.get("source") != "MCP_SCAN":
        return False
    evidence = row.get("evidence")
    return isinstance(evidence, dict) and bool(
        evidence.get("detector") == "mcp_enforcement" or evidence.get("mcp_auth_weakness") or evidence.get("mcp_tool_rule")
    )


def _asset_targets(identities: dict[str, set[str]], asset: dict, evidence: dict) -> set[str]:
    for identity in (asset.get("identifier"), evidence.get("server_canonical_id")):
        if isinstance(identity, str) and identity in identities:
            return identities[identity]
    return set()


def auth_server_index(graph: UnifiedGraph) -> dict[str, list[UnifiedNode]]:
    """Canonical server joins, with unique legacy labels only when IDs are absent."""
    identities: dict[str, list[UnifiedNode]] = defaultdict(list)
    labels: dict[str, list[UnifiedNode]] = defaultdict(list)
    for node in graph.nodes.values():
        if node.entity_type != EntityType.SERVER:
            continue
        identity = node.attributes.get("canonical_id") or node.attributes.get("stable_id")
        if identity:
            identities["id:" + str(identity)].append(node)
        labels[node.label].append(node)
    for label, nodes in labels.items():
        if len(nodes) == 1 and not (nodes[0].attributes.get("canonical_id") or nodes[0].attributes.get("stable_id")):
            identities["label:" + label] = nodes
    return identities
