"""The showcase's agent labels are the recorded names every other surface shows."""

from __future__ import annotations

from agent_bom.demo_estate.showcase_constants import SHOWCASE_AGENTS
from agent_bom.demo_estate.showcase_gateway import _FEED_EVENTS
from agent_bom.demo_estate.showcase_graph import build_showcase_graph
from agent_bom.demo_estate.showcase_identities import _DEMO_IDENTITIES


def test_langchain_service_is_labelled_without_an_unrecorded_suffix() -> None:
    assert SHOWCASE_AGENTS["langchain-service"] == "LangChain Service"
    graph, _, _ = build_showcase_graph(profile="current")
    assert graph.nodes["agent:langchain-service"].label == "LangChain Service"


def test_every_demo_surface_names_agents_by_their_graph_label() -> None:
    labels = set(SHOWCASE_AGENTS.values())
    assert {spec["agent_label"] for spec in _DEMO_IDENTITIES} <= labels
    # The feed also carries a deliberately unregistered caller.
    assert {row[1] for row in _FEED_EVENTS if "unregistered" not in row[1]} <= labels
