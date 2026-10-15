"""Graph node ids for the agents an interaction risk names.

Producers record agent names; a fleet- or endpoint-scoped agent's node is
``agent:<scope>:<name>`` and a Cortex Agent's is account-qualified, so a
hand-built ``agent:<name>`` misses both.
"""

from __future__ import annotations

from collections import defaultdict

from agent_bom.graph.container import InteractionRisk, UnifiedGraph
from agent_bom.graph.types import EntityType


def _agent_ids_by_name(graph: UnifiedGraph) -> dict[str, list[str]]:
    by_name: dict[str, list[str]] = defaultdict(list)
    for node in graph.iter_nodes_by_type(EntityType.AGENT):
        for name in {node.label, str(node.attributes.get("name") or "")} - {""}:
            by_name[name].append(node.id)
    return by_name


def interaction_risk_agent_ids(risk: InteractionRisk, graph: UnifiedGraph, by_name: dict[str, list[str]] | None = None) -> list[str]:
    """The risk's recorded node ids, else every agent node carrying one of its names."""
    if risk.agent_node_ids:
        return list(risk.agent_node_ids)
    index = _agent_ids_by_name(graph) if by_name is None else by_name
    ids: list[str] = []
    for name in risk.agents:
        ids.extend(sorted(index.get(name) or ([f"agent:{name}"] if graph.has_node(f"agent:{name}") else [])))
    return list(dict.fromkeys(ids))


def bind_interaction_risk_agent_ids(graph: UnifiedGraph) -> None:
    """Record node ids on every risk so later re-keys and readers need no name lookup."""
    if not graph.interaction_risks:
        return
    by_name = _agent_ids_by_name(graph)
    for risk in graph.interaction_risks:
        risk.agent_node_ids = interaction_risk_agent_ids(risk, graph, by_name)
