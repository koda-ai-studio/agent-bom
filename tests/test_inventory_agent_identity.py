"""An inventory agent keeps one id wherever its inventory file lives, and names the ids it had before."""

from __future__ import annotations

import hashlib

from agent_bom.canonical_ids import agent_graph_id, agent_graph_id_for, canonical_agent_id
from agent_bom.inventory import build_agents_from_inventory

_INVENTORY = {
    "schema_version": "1",
    "agents": [
        {"name": "billing-bot", "agent_type": "custom", "mcp_servers": []},
        {"name": "ops-bot", "agent_type": "custom", "config_path": "/etc/ops/agent.json", "mcp_servers": []},
    ],
}


def _agent(path: str, name: str = "billing-bot"):
    return next(agent for agent in build_agents_from_inventory(_INVENTORY, path) if agent.name == name)


def _path_based_graph_id(name: str, path: str) -> str:
    identity = canonical_agent_id("custom", name, config_path=path)
    return agent_graph_id(name, f"cfg-{hashlib.sha256(identity.encode()).hexdigest()[:12]}")


def test_same_agent_from_two_inventory_paths_has_one_id() -> None:
    first, second = _agent("/srv/a/inventory.json"), _agent("/home/ops/b/inventory.json")
    assert first.stable_id == second.stable_id
    assert first.canonical_id == second.canonical_id
    assert agent_graph_id_for(first) == agent_graph_id_for(second)


def test_inventory_path_is_still_shown_as_where_the_agent_was_read() -> None:
    assert _agent("/srv/a/inventory.json").config_path == "/srv/a/inventory.json"


def test_earlier_path_based_ids_are_kept_as_receipts() -> None:
    path = "/srv/a/inventory.json"
    agent = _agent(path)
    assert canonical_agent_id("custom", "billing-bot", config_path=path) in agent.previous_canonical_ids
    assert _path_based_graph_id("billing-bot", path) in agent.previous_graph_ids
    assert agent.stable_id not in agent.previous_canonical_ids
    assert agent_graph_id_for(agent) not in agent.previous_graph_ids


def test_an_agent_with_its_own_config_path_keeps_that_location_in_its_id() -> None:
    first, second = _agent("/srv/a/inventory.json", "ops-bot"), _agent("/home/b/inventory.json", "ops-bot")
    assert first.stable_id == second.stable_id == canonical_agent_id("custom", "ops-bot", config_path="/etc/ops/agent.json")


def test_two_agents_in_one_inventory_stay_distinct() -> None:
    agents = build_agents_from_inventory(_INVENTORY, "/srv/a/inventory.json")
    assert len({agent.stable_id for agent in agents}) == 2
    assert len({agent_graph_id_for(agent) for agent in agents}) == 2
