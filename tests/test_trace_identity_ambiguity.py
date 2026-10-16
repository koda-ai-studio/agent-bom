"""Explicit trace identifiers still require one compatible inventory identity."""

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.trace_projection import _Binder


def test_ambiguous_canonical_id_is_not_resolved_by_insertion_order():
    for ids in (("agent:a", "agent:b"), ("agent:b", "agent:a")):
        graph = UnifiedGraph()
        for node_id in ids:
            graph.add_node(
                UnifiedNode(id=node_id, entity_type=EntityType.AGENT, label="same", attributes={"canonical_id": "legacy-collision"})
            )
        binder = _Binder(graph)
        assert binder.node("legacy-collision") is None
        assert binder.node("agent:a").id == "agent:a"


def test_recorded_alias_is_accepted_only_for_one_target_and_never_overrides_live_id():
    graph = UnifiedGraph()
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="same", attributes={"identity": {"aliases": ["old"]}}))
    assert _Binder(graph).node("old").id == "agent:a"
    assert _Binder(graph).node("same") is None
    graph.add_node(
        UnifiedNode(id="agent:b", entity_type=EntityType.AGENT, label="same", attributes={"identity": {"aliases": ["old", "agent:a"]}})
    )
    assert _Binder(graph).node("old") is None
    assert _Binder(graph).node("agent:a").id == "agent:a"


def test_credential_name_without_server_scope_does_not_choose_first_slot():
    graph = UnifiedGraph()
    agent = UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a")
    graph.add_node(agent)
    for server in ("one", "two"):
        graph.add_node(UnifiedNode(id=server, entity_type=EntityType.SERVER, label=server))
        graph.add_node(UnifiedNode(id=f"cred:{server}:TOKEN", entity_type=EntityType.CREDENTIAL, label="TOKEN"))
        graph.add_edge(UnifiedEdge(source=agent.id, target=server, relationship=RelationshipType.USES))
    binder = _Binder(graph)
    assert binder.credential(agent, None, "TOKEN") is None
    assert binder.credential(agent, graph.get_node("one"), "TOKEN").id == "cred:one:TOKEN"
