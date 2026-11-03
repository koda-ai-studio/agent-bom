"""Build-workspace writes batch without changing live graph semantics."""

from collections import defaultdict

import pytest

from agent_bom.graph.build_workspace import open_workspace_backend
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.store_backed import StoreBackedUnifiedGraph
from agent_bom.graph.types import EntityType, RelationshipType


def test_single_item_build_calls_use_bounded_backend_batches(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_GRAPH_WRITE_BATCH_SIZE", "32")
    backend = open_workspace_backend(backend="sqlite")
    batches = defaultdict(list)
    for kind in ("node", "edge"):
        name = f"add_{kind}_payloads"
        original = getattr(backend, name)

        def record(tenant, rows, *, kind=kind, original=original):
            rows = list(rows)
            batches[kind].append(len(rows))
            return original(tenant, rows)

        monkeypatch.setattr(backend, name, record)
    try:
        graph = StoreBackedUnifiedGraph(backend, tenant_id="one", capacity=4)
        for index in range(128):
            graph.add_node(UnifiedNode(id=f"pkg:{index}", entity_type=EntityType.PACKAGE, label=str(index)))
            if index:
                graph.add_edge(UnifiedEdge(source=f"pkg:{index - 1}", target=f"pkg:{index}", relationship=RelationshipType.DEPENDS_ON))
        graph.flush()
        assert len(graph.nodes) == 128 and len(graph.edges) == 127
        assert 16 <= max(batches["node"]) <= 32
        assert 16 <= max(batches["edge"]) <= 32
        assert len(batches["node"]) <= 12
        assert len(batches["edge"]) <= 8
        assert graph.get_node("pkg:0").label == "0"
        assert graph.reachable_from("pkg:0", max_depth=128) >= {"pkg:1", "pkg:127"}
        assert not StoreBackedUnifiedGraph(backend, tenant_id="two").nodes
    finally:
        backend.close()


@pytest.mark.parametrize("kind", ["node", "edge"])
def test_failed_batch_retains_pending_rows_for_retry(monkeypatch, kind):
    from agent_bom.graph.workspace_writes import WorkspaceWrites

    backend = open_workspace_backend(backend="sqlite")
    writes = WorkspaceWrites(backend, "one")
    name = f"add_{kind}_payloads"
    original = getattr(backend, name)

    def fail(*args):
        raise OSError("test workspace unavailable")

    row = ("id", "{}", "package") if kind == "node" else ("id", "{}", "source", "target")
    try:
        getattr(writes, f"add_{kind}")(row)
        monkeypatch.setattr(backend, name, fail)
        with pytest.raises(OSError, match="test workspace unavailable"):
            writes.flush()
        assert getattr(writes, f"{kind}_payload")("id") == "{}"
        monkeypatch.setattr(backend, name, original)
        writes.flush()
        assert getattr(writes, f"{kind}_payload")("id") is None
        assert getattr(backend, f"get_{kind}_payload")("one", "id") == "{}"
    finally:
        backend.close()


def test_failed_build_does_not_flush_or_mask_original_error(monkeypatch):
    backend = open_workspace_backend(backend="sqlite")
    graph = StoreBackedUnifiedGraph(backend)
    calls = []
    monkeypatch.setattr(graph, "flush", lambda: calls.append("flush"))
    try:
        with pytest.raises(ValueError, match="original build error"), graph:
            raise ValueError("original build error")
        assert calls == []
    finally:
        backend.close()
