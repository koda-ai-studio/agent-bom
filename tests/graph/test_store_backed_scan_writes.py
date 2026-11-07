"""Read-only passes over a store-backed graph do not rewrite the nodes they read."""

from __future__ import annotations

from typing import Any

import pytest

from agent_bom.graph.build_workspace import open_workspace_backend
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.store_backed import StoreBackedUnifiedGraph, open_store_backed_unified_graph
from agent_bom.graph.types import EntityType
from scripts.generate_graph_benchmark_estate import generate_estate

_MIXED = (
    ("pkg:1", EntityType.PACKAGE),
    ("srv:1", EntityType.SERVER),
    ("agent:1", EntityType.AGENT),
    ("pkg:2", EntityType.PACKAGE),
    ("srv:2", EntityType.SERVER),
    ("tool:1", EntityType.TOOL),
    ("agent:2", EntityType.AGENT),
)
_WANTED = (EntityType.SERVER, EntityType.AGENT)
_WANTED_IDS = ["srv:1", "agent:1", "srv:2", "agent:2"]


def _populate(graph: UnifiedGraph) -> None:
    for node_id, entity_type in _MIXED:
        graph.add_node(UnifiedNode(id=node_id, entity_type=entity_type, label=node_id))


@pytest.fixture
def store_graph() -> Any:
    backend = open_workspace_backend(backend="sqlite")
    graph = StoreBackedUnifiedGraph(backend, tenant_id="one", capacity=2)
    _populate(graph)
    graph.flush()
    try:
        yield graph
    finally:
        backend.close()


@pytest.fixture
def containers(store_graph: StoreBackedUnifiedGraph) -> list[UnifiedGraph]:
    memory = UnifiedGraph(tenant_id="one")
    _populate(memory)
    return [memory, store_graph]


def _count_rewrites(monkeypatch: pytest.MonkeyPatch, graph: StoreBackedUnifiedGraph) -> list[str]:
    rewrites: list[str] = []
    original = graph._write_back

    def record(node_id: str, node: UnifiedNode) -> None:
        rewrites.append(node_id)
        original(node_id, node)

    monkeypatch.setattr(graph, "_write_back", record)
    return rewrites


def test_full_read_only_pass_rewrites_nothing(monkeypatch: pytest.MonkeyPatch, store_graph: StoreBackedUnifiedGraph) -> None:
    rewrites = _count_rewrites(monkeypatch, store_graph)
    assert [node.id for node in store_graph.iter_nodes()] == [node_id for node_id, _ in _MIXED]
    store_graph.flush()
    assert rewrites == []


def test_typed_read_only_pass_rewrites_nothing(monkeypatch: pytest.MonkeyPatch, store_graph: StoreBackedUnifiedGraph) -> None:
    rewrites = _count_rewrites(monkeypatch, store_graph)
    assert [node.id for node in store_graph.iter_nodes_of_types(_WANTED)] == _WANTED_IDS
    store_graph.flush()
    assert rewrites == []


def test_typed_passes_keep_insertion_order_on_both_containers(containers: list[UnifiedGraph]) -> None:
    for graph in containers:
        assert [node.id for node in graph.iter_nodes_of_types(_WANTED)] == _WANTED_IDS
        assert [node.id for node in graph.nodes_of_types(_WANTED)] == _WANTED_IDS
        assert [node.id for node in graph.iter_nodes()] == [node_id for node_id, _ in _MIXED]


def test_typed_pass_with_no_matching_type_is_empty(containers: list[UnifiedGraph]) -> None:
    for graph in containers:
        assert list(graph.iter_nodes_of_types((EntityType.CLUSTER,))) == []
        assert graph.nodes_of_types(()) == []


def test_writable_typed_list_keeps_mutations_after_eviction(store_graph: StoreBackedUnifiedGraph) -> None:
    held = store_graph.nodes_of_types((EntityType.TOOL,))
    held[0].attributes["marked"] = True
    assert [node.id for node in store_graph.iter_nodes_of_types((EntityType.PACKAGE, EntityType.SERVER, EntityType.AGENT))]
    store_graph.flush()
    store_graph._cache.clear()
    assert store_graph.get_node("tool:1").attributes["marked"] is True


def test_typed_pass_stays_inside_the_tenant() -> None:
    backend = open_workspace_backend(backend="sqlite")
    try:
        first = StoreBackedUnifiedGraph(backend, tenant_id="one")
        second = StoreBackedUnifiedGraph(backend, tenant_id="two")
        first.add_node(UnifiedNode(id="srv:one", entity_type=EntityType.SERVER, label="one"))
        second.add_node(UnifiedNode(id="srv:two", entity_type=EntityType.SERVER, label="two"))
        assert [node.id for node in first.iter_nodes_of_types((EntityType.SERVER,))] == ["srv:one"]
        assert [node.id for node in second.iter_nodes()] == ["srv:two"]
    finally:
        backend.close()


def test_reads_after_writes_finish_rewrite_nothing(monkeypatch: pytest.MonkeyPatch, store_graph: StoreBackedUnifiedGraph) -> None:
    store_graph.finish_writes()
    rewrites = _count_rewrites(monkeypatch, store_graph)
    assert len(list(store_graph.nodes.values())) == len(_MIXED)
    assert store_graph.nodes.get("pkg:1") is not None
    assert store_graph.nodes["srv:1"].label == "srv:1"
    assert [node_id for node_id, _node in store_graph.nodes.items()] == [node_id for node_id, _ in _MIXED]
    store_graph.flush()
    assert rewrites == []


def test_explicit_changes_after_writes_finish_stay_durable(store_graph: StoreBackedUnifiedGraph) -> None:
    store_graph.finish_writes()
    store_graph.get_node("tool:1").attributes["changed"] = True
    late = UnifiedNode(id="late:1", entity_type=EntityType.TOOL, label="late")
    store_graph.add_node(late)
    late.attributes["changed"] = True
    assert list(store_graph.iter_nodes())
    store_graph.flush()
    store_graph._cache.clear()
    assert store_graph.get_node("tool:1").attributes["changed"] is True
    assert store_graph.get_node("late:1").attributes["changed"] is True


def test_finish_writes_keeps_pending_changes(store_graph: StoreBackedUnifiedGraph) -> None:
    store_graph.nodes["pkg:1"].attributes["pending"] = True
    store_graph.finish_writes()
    store_graph._cache.clear()
    assert store_graph.get_node("pkg:1").attributes["pending"] is True


def test_in_memory_graph_accepts_finish_writes() -> None:
    memory = UnifiedGraph(tenant_id="one")
    _populate(memory)
    memory.finish_writes()
    memory.nodes["pkg:1"].attributes["changed"] = True
    assert memory.get_node("pkg:1").attributes["changed"] is True


def test_building_an_estate_rewrites_each_node_a_bounded_number_of_times(monkeypatch: pytest.MonkeyPatch) -> None:
    """With a small cache a read that marks a node dirty costs a rewrite, so this counts passes that rewrite."""
    report, _summary = generate_estate(agents=25, seed=2145, vulnerable_package_rate=0.08)
    rewrites = 0
    original = StoreBackedUnifiedGraph._write_back

    def record(self: StoreBackedUnifiedGraph, node_id: str, node: UnifiedNode) -> None:
        nonlocal rewrites
        rewrites += 1
        original(self, node_id, node)

    monkeypatch.setattr(StoreBackedUnifiedGraph, "_write_back", record)
    with open_store_backed_unified_graph(tenant_id="one", scan_id="s", backend="sqlite", capacity=64) as container:
        graph = build_unified_graph_from_report(report, scan_id="s", tenant_id="one", container=container)
        nodes = len(graph.nodes)
    assert nodes > 500
    assert rewrites <= 8 * nodes, f"{rewrites} rewrites for {nodes} nodes"
