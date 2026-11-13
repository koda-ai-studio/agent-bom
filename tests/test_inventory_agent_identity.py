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


def _team_inventory(source: str, server: str) -> dict:
    agent = {"name": "assistant", "agent_type": "custom", "mcp_servers": [{"name": server, "command": "npx", "args": [server]}]}
    return {"schema_version": "1", "source": source, "agents": [agent]}


def _team_agent(source: str, server: str, path: str, **extra: str):
    return build_agents_from_inventory({**_team_inventory(source, server), **extra}, path)[0]


def test_same_name_in_two_declared_sources_stays_two_agents() -> None:
    payments = _team_agent("payments-cmdb", "ledger", "/srv/payments/inventory.json")
    hr = _team_agent("hr-cmdb", "people", "/srv/hr/inventory.json")
    assert payments.stable_id != hr.stable_id
    assert agent_graph_id_for(payments) != agent_graph_id_for(hr)


def test_declared_source_id_wins_over_source_name() -> None:
    first = _team_agent("cmdb", "a", "/x/inventory.json", source_id="inv-7")
    renamed = _team_agent("cmdb-renamed", "a", "/x/inventory.json", source_id="inv-7")
    assert first.stable_id == renamed.stable_id


def test_source_scoped_id_survives_a_moved_inventory_file() -> None:
    first = _team_agent("payments-cmdb", "ledger", "/srv/payments/inventory.json")
    moved = _team_agent("payments-cmdb", "ledger", "/mnt/new/inventory.json")
    assert first.stable_id == moved.stable_id
    assert agent_graph_id_for(first) == agent_graph_id_for(moved)


def test_source_scoped_agent_names_its_location_free_and_path_ids_as_receipts() -> None:
    path = "/srv/payments/inventory.json"
    agent = _team_agent("payments-cmdb", "ledger", path)
    assert canonical_agent_id("custom", "assistant", config_path="") in agent.previous_canonical_ids
    assert canonical_agent_id("custom", "assistant", config_path=path) in agent.previous_canonical_ids
    assert _path_based_graph_id("assistant", "") in agent.previous_graph_ids
    assert _path_based_graph_id("assistant", path) in agent.previous_graph_ids
    assert agent.stable_id not in agent.previous_canonical_ids
    assert agent_graph_id_for(agent) not in agent.previous_graph_ids


def test_serialized_report_rows_keep_the_two_teams_apart_in_the_graph() -> None:
    """Graph producers read the exported identity, not the model; the export must carry the scoped id."""
    from agent_bom.canonical_ids import agent_identity_export

    rows = []
    for source, server, path in (
        ("payments-cmdb", "ledger", "/srv/payments/inventory.json"),
        ("hr-cmdb", "people", "/srv/hr/inventory.json"),
    ):
        agent = _team_agent(source, server, path)
        rows.append({"name": agent.name, "agent_type": "custom", "config_path": "inventory.json", **agent_identity_export(agent)})
    assert len({agent_graph_id_for(row) for row in rows}) == 2


def test_inventory_without_source_identity_keeps_the_location_free_id() -> None:
    assert _agent("/srv/a/inventory.json").stable_id == canonical_agent_id("custom", "billing-bot", config_path="")


def test_two_agents_in_one_inventory_stay_distinct() -> None:
    agents = build_agents_from_inventory(_INVENTORY, "/srv/a/inventory.json")
    assert len({agent.stable_id for agent in agents}) == 2
    assert len({agent_graph_id_for(agent) for agent in agents}) == 2
