"""Vulnerability occurrence checks. Missing local exploitability stays unknown."""

from __future__ import annotations

from agent_bom.graph.consequence.contracts import ConsequenceRequest, Prerequisites
from agent_bom.graph.consequence.identity import PRINCIPALS
from agent_bom.graph.consequence.prerequisite_checks import collected_checks
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import EntityType, RelationshipType


def starting_state(graph: UnifiedGraph, request: ConsequenceRequest) -> tuple[str, Prerequisites]:
    root = graph.nodes.get(request.root_node_id)
    if root is None:
        raise ValueError("root not found")
    if request.mode == "assumed_compromise":
        if root.entity_type not in PRINCIPALS | {EntityType.AGENT}:
            raise ValueError("assumed control requires an agent or principal")
        return root.id, Prerequisites(status="not_evaluated")
    affected = graph.nodes.get(request.affected_node_id or "")
    if root.entity_type != EntityType.VULNERABILITY or affected is None:
        raise ValueError("vulnerability requires a recorded affected occurrence")
    linked = [
        edge
        for edge in graph.edges
        if (edge.source == root.id and edge.target == affected.id and edge.relationship == RelationshipType.AFFECTS)
        or (edge.source == affected.id and edge.target == root.id and edge.relationship == RelationshipType.VULNERABLE_TO)
    ]
    if not linked:
        raise ValueError("affected occurrence is not linked to this vulnerability")
    # ExploitabilityDimension currently has a reader but no occurrence-scoped
    # collector producer. Do not treat imported generic verdicts, CVSS or EPSS
    # as proof of deployed version/configuration, entry point and prerequisites.
    return affected.id, Prerequisites(
        status="unknown",
        checks=collected_checks(root, linked),
        evidence_refs=[edge.id for edge in linked],
        reason_codes=[
            "local_exploitability_not_collected",
            "deployed_configuration_unverified",
            "entry_point_unverified",
        ],
    )
