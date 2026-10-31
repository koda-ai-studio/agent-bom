"""Agent platform, execution location and model service are independent facts."""

from agent_bom.graph.builder import build_unified_graph_from_report


def test_agent_platform_does_not_claim_the_vendor_hosts_the_agent():
    graph = build_unified_graph_from_report({"agents": [{"name": "developer", "type": "claude-code", "mcp_servers": []}]})
    agent = next(node for node in graph.nodes.values() if node.entity_type.value == "agent")
    incoming = graph.edges_to(agent.id)
    assert any(edge.relationship.value == "platform_for" for edge in incoming)
    assert all(not edge.traversable for edge in incoming if edge.relationship.value == "platform_for")
    assert not any(edge.relationship.value == "hosts" for edge in incoming)
    context = agent.attributes.get("agent_context", {})
    assert context.get("schema_version") == "agent.context.v1"
    assert context["agent_kind"] == "claude-code"
    assert context["execution"]["status"] == "not_recorded"
    assert context["models"]["status"] == "not_recorded"


def test_cloud_origin_host_is_distinct_from_agent_kind():
    graph = build_unified_graph_from_report(
        {
            "agents": [
                {
                    "name": "developer",
                    "type": "claude-code",
                    "mcp_servers": [],
                    "metadata": {
                        "cloud_origin": {
                            "provider": "aws",
                            "service": "ec2",
                            "resource_type": "instance",
                            "resource_id": "i-test-host",
                            "scope": {"account_id": "account-a"},
                        }
                    },
                }
            ]
        }
    )
    agent = next(node for node in graph.nodes.values() if node.entity_type.value == "agent")
    context = agent.attributes.get("agent_context", {})
    assert context.get("agent_kind") == "claude-code"
    assert context["execution"]["status"] == "recorded"
    host = context["execution"]["items"][0]
    assert host["relationship"] == "hosted_on"
    assert host["provider"] == "aws"
    assert host["service"] == "ec2"
    assert host.get("account_id") == "account-a"
    assert context["models"]["status"] == "not_recorded"


def _context_graph():
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.types import EntityType as E
    from agent_bom.graph.types import RelationshipType as R

    graph = UnifiedGraph(tenant_id="tenant-a", scan_id="scope-a")
    graph.add_node(UnifiedNode("agent:a", E.AGENT, "workflow", attributes={"agent_type": "workflow"}))
    graph.add_node(UnifiedNode("env:a", E.ENVIRONMENT, "Production AI", attributes={"cloud_provider": "aws"}))
    graph.add_node(UnifiedNode("model:a", E.MODEL, "recorded-model", attributes={"cloud_provider": "gcp"}))
    evidence = {"source": "configuration", "tier": "declared"}
    graph.add_edge(UnifiedEdge("env:a", "agent:a", R.CONTAINS, evidence=evidence))
    graph.add_edge(UnifiedEdge("agent:a", "model:a", R.SERVES_MODEL, evidence=evidence))
    return graph


def test_membership_and_model_provider_do_not_supply_execution_location():
    from agent_bom.graph.agent_context import annotate_agent_context

    graph = _context_graph()
    annotate_agent_context(graph)
    context = graph.nodes["agent:a"].attributes["agent_context"]
    assert context["execution"]["status"] == "not_recorded"
    assert context["platforms"]["status"] == "not_recorded"
    assert context["membership"]["items"][0]["provider"] == "aws"
    assert context["models"]["items"][0]["provider"] == "gcp"
    assert context["models"]["items"][0]["source"] == "configuration"
    assert context["models"]["items"][0]["evidence_kind"] == "declared"


def test_agent_context_is_bounded_and_persists_after_cache_eviction():
    from agent_bom.graph.agent_context import CONTEXT_ITEM_LIMIT, annotate_agent_context
    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.store_backed import open_store_backed_unified_graph
    from agent_bom.graph.types import EntityType as E
    from agent_bom.graph.types import RelationshipType as R

    graph = open_store_backed_unified_graph(backend="sqlite", capacity=1, tenant_id="tenant-a", scan_id="bounded")
    try:
        graph.add_node(UnifiedNode("agent:a", E.AGENT, "workflow"))
        for i in range(CONTEXT_ITEM_LIMIT + 3):
            graph.add_node(UnifiedNode(f"host:{i}", E.CONTAINER, f"host-{i}"))
            graph.add_edge(UnifiedEdge("agent:a", f"host:{i}", R.HOSTED_ON, evidence={"source": "test", "tier": "declared"}))
        annotate_agent_context(graph)
        graph.nodes["host:0"]  # evict the agent before reading its serialized row
        context = graph.nodes["agent:a"].attributes.get("agent_context", {})
        assert context.get("schema_version") == "agent.context.v1"
        assert len(context["execution"]["items"]) == CONTEXT_ITEM_LIMIT
        assert context["execution"]["recorded_count"] == CONTEXT_ITEM_LIMIT + 3
        assert context["execution"]["truncated"] is True
    finally:
        graph.close()


def test_context_bounds_labels_without_copying_unrelated_node_attributes():
    from agent_bom.graph.agent_context import annotate_agent_context

    graph = _context_graph()
    graph.nodes["model:a"].label = "x" * 1000
    graph.nodes["model:a"].attributes["credential_value"] = "must-not-copy"
    annotate_agent_context(graph)
    item = graph.nodes["agent:a"].attributes["agent_context"]["models"]["items"][0]
    assert len(item["label"]) <= 200
    assert "credential_value" not in item


def test_inventory_view_preserves_platform_association_without_attack_traversal():
    graph = build_unified_graph_from_report({"agents": [{"name": "developer", "type": "claude-code", "mcp_servers": []}]})
    assert any(edge.relationship.value == "platform_for" for edge in graph.inventory_view().edges)
    assert not any(edge.relationship.value == "platform_for" for edge in graph.attack_path_view().edges)


def test_showcase_provider_is_a_platform_not_an_execution_host():
    from agent_bom.demo_estate.showcase_graph import build_showcase_graph

    graph, _, _ = build_showcase_graph()
    links = [
        edge
        for edge in graph.edges
        if graph.nodes[edge.source].entity_type.value == "provider" and graph.nodes[edge.target].entity_type.value == "agent"
    ]
    assert links
    assert all(edge.relationship.value == "platform_for" and not edge.traversable for edge in links)


def test_exact_endpoint_binding_is_host_context_but_logical_fleet_is_not():
    from agent_bom.graph.agent_context import annotate_agent_context
    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.types import EntityType as E
    from agent_bom.graph.types import RelationshipType as R

    graph = _context_graph()
    graph.add_node(UnifiedNode("endpoint:a", E.FLEET, "workstation", attributes={"endpoint_id": "a"}))
    graph.add_node(UnifiedNode("fleet:a", E.FLEET, "logical fleet"))
    graph.add_edge(
        UnifiedEdge(
            "endpoint:a",
            "agent:a",
            R.HOSTS,
            evidence={
                "source": "endpoint_inventory",
                "tier": "static_scan",
                "identity_match_basis": "exact_source_id",
                "execution_proven": False,
            },
        )
    )
    graph.add_edge(UnifiedEdge("fleet:a", "agent:a", R.HOSTS))
    annotate_agent_context(graph)
    context = graph.nodes["agent:a"].attributes["agent_context"]
    assert [item["node_id"] for item in context["execution"]["items"]] == ["endpoint:a"]
    assert context["execution"]["items"][0]["evidence_kind"] == "static_scan"


def test_correlated_context_uses_final_node_identities_and_keeps_inputs_immutable():
    from agent_bom.graph.agent_context import annotate_agent_context
    from agent_bom.graph.correlation import CorrelationSnapshot, merge_graph_snapshots

    graphs = [_context_graph(), _context_graph()]
    snapshots = []
    for i, graph in enumerate(graphs):
        graph.scan_id = f"scope-{i}"
        annotate_agent_context(graph)
        snapshots.append(CorrelationSnapshot.from_graph(graph))
    result = merge_graph_snapshots(correlation_id="joined", tenant_id="tenant-a", snapshots=snapshots)
    for agent in result.graph.nodes.values():
        if agent.entity_type.value != "agent":
            continue
        context = agent.attributes["agent_context"]
        for category in ("membership", "models"):
            assert context[category]["items"]
            for item in context[category]["items"]:
                assert item["node_id"] in result.graph.nodes
    assert graphs[0].nodes["agent:a"].attributes["agent_context"]["models"]["items"][0]["node_id"] == "model:a"
