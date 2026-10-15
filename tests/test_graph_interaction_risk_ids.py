"""Interaction risks resolve to the scoped agent nodes they describe."""

from __future__ import annotations

from agent_bom.api.routes.graph_routes.payloads import _filtered_graph_response
from agent_bom.graph.container import InteractionRisk, UnifiedGraph
from agent_bom.graph.interaction_risk_ids import bind_interaction_risk_agent_ids, interaction_risk_agent_ids
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType
from agent_bom.graph.webhooks import compute_delta_alerts


def _graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="s1")
    for node_id, label in (("agent:fleet-1:alpha", "alpha"), ("agent:fleet-1:beta", "beta")):
        graph.add_node(UnifiedNode(id=node_id, entity_type=EntityType.AGENT, label=label))
    graph.interaction_risks.append(InteractionRisk(pattern="shared_credential", agents=["alpha", "beta"], risk_score=8.5, description=""))
    return graph


def test_scoped_agents_resolve_by_name() -> None:
    graph = _graph()
    assert interaction_risk_agent_ids(graph.interaction_risks[0], graph) == ["agent:fleet-1:alpha", "agent:fleet-1:beta"]
    bind_interaction_risk_agent_ids(graph)
    assert graph.interaction_risks[0].agent_node_ids == ["agent:fleet-1:alpha", "agent:fleet-1:beta"]


def test_filtered_graph_keeps_risks_on_scoped_agents() -> None:
    payload = _filtered_graph_response(_graph(), offset=0, limit=50)
    assert [risk["pattern"] for risk in payload["interaction_risks"]] == ["shared_credential"]


def test_delta_alert_names_scoped_agent_nodes() -> None:
    alerts = [alert for alert in compute_delta_alerts(None, _graph()) if alert["type"] == "new_interaction_risk"]
    assert alerts and alerts[0]["details"]["node_ids"] == ["agent:fleet-1:alpha", "agent:fleet-1:beta"]
