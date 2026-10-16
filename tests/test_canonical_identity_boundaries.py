"""Identifier structure and case are evidence, not label normalization."""

from agent_bom.canonical_ids import (
    agent_graph_id,
    canonical_agent_id,
    canonical_graph_edge_id,
    canonical_graph_node_id,
    canonical_id,
    canonical_mcp_prompt_id,
    canonical_mcp_resource_id,
    canonical_mcp_tool_id,
)


def test_canonical_identity_preserves_component_boundaries():
    assert canonical_id("a:b", "c") != canonical_id("a", "b:c")
    assert canonical_id("a", "", "b") != canonical_id("a", "b")
    assert canonical_id("a", None) != canonical_id("a", "None")


def test_case_sensitive_tool_resource_and_prompt_identifiers_stay_distinct():
    assert canonical_mcp_tool_id("Read", server_id="server") != canonical_mcp_tool_id("read", server_id="server")
    assert canonical_mcp_resource_id("file:///Data") != canonical_mcp_resource_id("file:///data")
    assert canonical_mcp_prompt_id("Review") != canonical_mcp_prompt_id("review")


def test_graph_canonical_identifiers_preserve_case_and_endpoints():
    assert canonical_graph_node_id("tool", "tool:Read") != canonical_graph_node_id("tool", "tool:read")
    assert canonical_graph_edge_id("a:b", "c", "uses") != canonical_graph_edge_id("a", "b:c", "uses")


def test_config_path_case_is_not_erased_from_agent_identity():
    assert canonical_agent_id("custom", "same", config_path="/work/Team/mcp.json") != canonical_agent_id(
        "custom", "same", config_path="/work/team/mcp.json"
    )


def test_scope_escaping_does_not_alias_literal_percent_sequences():
    assert agent_graph_id("agent", "a:b") != agent_graph_id("agent", "a%3Ab")
    assert agent_graph_id("b:c", "a") != agent_graph_id("c", "a:b")


def test_fleet_legacy_alias_cannot_override_a_different_config_path():
    from agent_bom.api.fleet_models import FleetAgent
    from agent_bom.api.fleet_store import match_discovered_fleet_agent

    existing = FleetAgent(
        agent_id="old", canonical_id="legacy-collision", name="same", agent_type="custom", config_path="/work/Team/mcp.json"
    )
    assert (
        match_discovered_fleet_agent(
            [existing],
            canonical_id="new",
            agent_type="custom",
            name="same",
            config_path="/work/team/mcp.json",
            previous_canonical_ids=["legacy-collision"],
        )
        is None
    )


def test_fleet_name_does_not_join_a_source_scoped_agent_to_unqualified_discovery():
    from agent_bom.api.fleet_models import FleetAgent
    from agent_bom.api.fleet_store import match_discovered_fleet_agent

    existing = FleetAgent(agent_id="old", canonical_id="source-one", name="same", agent_type="custom", source_id="source-one")
    assert match_discovered_fleet_agent([existing], canonical_id="source-two", agent_type="custom", name="same", config_path="") is None


def test_all_config_scoped_agents_remain_distinct_in_graph_and_export():
    from agent_bom.canonical_ids import agent_graph_id_for
    from agent_bom.graph.builder import build_unified_graph_from_report
    from agent_bom.graph.types import EntityType
    from agent_bom.models import Agent, AgentType, AIBOMReport
    from agent_bom.output.json_fmt import to_json

    agents = [
        Agent(name="same", agent_type=AgentType.CUSTOM, config_path=path, source="local")
        for path in ("/work/Team/mcp.json", "/work/team/mcp.json")
    ]
    report = to_json(AIBOMReport(agents=agents, blast_radii=[], tool_version="0.0.0"))
    graph = build_unified_graph_from_report(report)
    model_ids = {agent_graph_id_for(agent) for agent in agents}
    assert len(model_ids) == 2
    assert model_ids == {node.id for node in graph.nodes.values() if node.entity_type == EntityType.AGENT}
    assert model_ids == {agent_graph_id_for(agent) for agent in report["agents"]}


def test_v2_fleet_migration_retains_approval_and_does_not_claim_case_collision():
    from unittest.mock import patch

    from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState, InMemoryFleetStore
    from agent_bom.api.pipeline import _sync_scan_agents_to_fleet
    from agent_bom.canonical_ids import legacy_agent_id_v2
    from agent_bom.models import Agent, AgentType

    store = InMemoryFleetStore()
    first = Agent(name="same", agent_type=AgentType.CUSTOM, config_path="/work/Team/mcp.json")
    second = Agent(name="same", agent_type=AgentType.CUSTOM, config_path="/work/team/mcp.json")
    legacy_id = legacy_agent_id_v2("custom", "same", config_path=first.config_path)
    assert legacy_id in first.previous_canonical_ids and legacy_id in second.previous_canonical_ids
    store.put(
        FleetAgent(
            agent_id="approved-row",
            canonical_id=legacy_id,
            name=first.name,
            agent_type="custom",
            config_path=first.config_path,
            lifecycle_state=FleetLifecycleState.APPROVED,
            tenant_id="default",
        )
    )
    with patch("agent_bom.api.pipeline._get_fleet_store", return_value=store):
        _sync_scan_agents_to_fleet([second, first])
        _sync_scan_agents_to_fleet([first, second])
    rows = store.list_by_tenant("default")
    assert len(rows) == 2
    assert store.get("approved-row", tenant_id="default").canonical_id == first.canonical_id
    assert store.get("approved-row", tenant_id="default").lifecycle_state == FleetLifecycleState.APPROVED
    assert store.get_by_canonical_id(second.canonical_id, "default").lifecycle_state != FleetLifecycleState.APPROVED


def test_stored_v2_edge_identity_survives_read_and_export():
    from agent_bom.canonical_ids import legacy_canonical_id_v2
    from agent_bom.graph import RelationshipType, UnifiedEdge

    recorded = legacy_canonical_id_v2("graph_edge", "uses", "agent:old", "server:old")
    payload = UnifiedEdge(source="agent:old", target="server:old", relationship=RelationshipType.USES).to_dict()
    payload["canonical_id"] = recorded
    assert UnifiedEdge.from_dict(payload).to_dict()["canonical_id"] == recorded


def test_exposure_finding_count_does_not_count_its_label_as_another_occurrence():
    from agent_bom.graph import AttackPath, EntityType, UnifiedNode
    from agent_bom.graph.exposure import _exposure_path_for_attack_path
    from agent_bom.mcp_tools.exposure_queue import summary_path

    node = UnifiedNode(
        id="misconfig:one",
        entity_type=EntityType.MISCONFIGURATION,
        label="A descriptive finding",
        attributes={"finding_id": "occurrence-one"},
    )
    path = AttackPath(source="agent:a", target=node.id, hops=["agent:a", node.id], vuln_ids=[node.label, "CVE-other"])
    full = _exposure_path_for_attack_path(path, nodes_by_id={node.id: node})
    summary = summary_path(full)
    assert full["findings"] == summary["findings"] == ["occurrence-one", "CVE-other"]
    assert summary["findingCount"] == 2


def graph_identity_storage_contract(store, tenant="identity-contract"):
    from agent_bom.canonical_ids import legacy_canonical_id_v2
    from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode

    for schema in ("2", "3"):
        graph = UnifiedGraph(tenant_id=tenant, scan_id="identity-" + schema)
        for node_id in ("agent:Read", "server:Read"):
            kind = EntityType.AGENT if node_id.startswith("agent:") else EntityType.SERVER
            node = UnifiedNode(id=node_id, entity_type=kind, label="Read")
            if schema == "2":
                node = UnifiedNode.from_dict({**node.to_dict(), "canonical_id": legacy_canonical_id_v2("graph_node", kind.value, node_id)})
            graph.add_node(node)
        edge = UnifiedEdge(source="agent:Read", target="server:Read", relationship=RelationshipType.USES)
        if schema == "2":
            edge = UnifiedEdge.from_dict(
                {**edge.to_dict(), "canonical_id": legacy_canonical_id_v2("graph_edge", "uses", edge.source, edge.target)}
            )
        graph.add_edge(edge)
        store.save_graph(graph)
        loaded = store.load_graph(tenant_id=tenant, scan_id=graph.scan_id)
        assert {key: n.canonical_id for key, n in loaded.nodes.items()} == {key: n.canonical_id for key, n in graph.nodes.items()}
        assert [e.canonical_id for e in loaded.edges] == [e.canonical_id for e in graph.edges]
        assert all("_agent_bom_canonical_id" not in n.to_dict()["attributes"] for n in loaded.nodes.values())
        assert all("_agent_bom_canonical_id" not in e.to_dict()["provenance"] for e in loaded.edges)
        paged = store.nodes_by_ids(tenant_id=tenant, scan_id=graph.scan_id, node_ids=set(graph.nodes))
        assert {n.id: n.canonical_id for n in paged} == {key: n.canonical_id for key, n in graph.nodes.items()}
    assert not store.load_graph(tenant_id="other-tenant", scan_id="identity-3").nodes
    # Internal persistence receipts do not become searchable source evidence.
    results, total, _ = store.search_nodes(tenant_id=tenant, scan_id="identity-3", query="_", offset=0, limit=10)
    assert total == 0 and results == []
    assert store.changed_edges_between_scans("identity-2", "identity-3", tenant_id=tenant)["edges_changed"] == []


def test_graph_storage_keeps_v2_and_v3_canonical_ids(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    graph_identity_storage_contract(SQLiteGraphStore(tmp_path / "identity.db"))


def test_unstamped_historical_rows_keep_v2_identity():
    from agent_bom.canonical_ids import legacy_canonical_id_v2
    from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedNode

    node = UnifiedNode.from_stored(id="agent:Read", entity_type=EntityType.AGENT, label="Read")
    edge = UnifiedEdge.from_stored(source=node.id, target="server:Read", relationship=RelationshipType.USES)
    assert node.canonical_id == legacy_canonical_id_v2("graph_node", "agent", node.id)
    assert edge.canonical_id == legacy_canonical_id_v2("graph_edge", "uses", node.id, edge.target)


def test_server_aliases_retain_frozen_scope_escaping_and_registry_v2_ids():
    from agent_bom.canonical_ids import canonical_mcp_server_id, legacy_canonical_id_v2, previous_mcp_server_graph_ids

    agent = {"name": "one", "source_id": "host%3Aone"}
    server = {"name": "same", "command": "npx", "args": ["foo"]}
    identity = canonical_mcp_server_id("same", "npx", args=["foo"])
    assert f"server:host%3Aone:{identity}" in previous_mcp_server_graph_ids({**server, "canonical_id": identity}, agent)
    registry = {"name": "registered", "registry_id": "org.example/service"}
    registry["canonical_id"] = canonical_mcp_server_id(registry["name"], registry_id=registry["registry_id"])
    assert f"server:{legacy_canonical_id_v2('mcp_server', registry['registry_id'])}" in previous_mcp_server_graph_ids(registry, agent)
