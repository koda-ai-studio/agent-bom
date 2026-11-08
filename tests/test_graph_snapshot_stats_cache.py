"""Snapshot stats are computed once per committed snapshot revision, per tenant and filter.

The relationship breakdown walks every edge of the snapshot. A graph page read
it on every request, so a 230k-edge estate spent 0.3-0.8 s per page on a
number that cannot change until the snapshot is written again.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _graph(tenant: str, scan_id: str, packages: int) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=tenant)
    graph.add_node(UnifiedNode(id="root", entity_type=EntityType.PACKAGE, label="root"))
    for index in range(packages):
        graph.add_node(UnifiedNode(id=f"p{index}", entity_type=EntityType.PACKAGE, label=f"package-{index}"))
        graph.add_edge(UnifiedEdge(source="root", target=f"p{index}", relationship=RelationshipType.DEPENDS_ON, traversable=True))
    return graph


@pytest.fixture()
def traced(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    statements: list[str] = []
    original = SQLiteGraphStore._open_ro_conn

    def open_traced(self: SQLiteGraphStore, **kwargs: Any) -> sqlite3.Connection | None:
        conn = original(self, **kwargs)
        if conn is not None:
            conn.set_trace_callback(statements.append)
        return conn

    monkeypatch.setattr(SQLiteGraphStore, "_open_ro_conn", open_traced)
    return statements


def _edge_scans(statements: list[str]) -> int:
    return sum("FROM graph_edges" in statement for statement in statements)


@pytest.mark.parametrize("filters", [{}, {"entity_types": {"package"}}, {"min_severity_rank": 1}])
def test_repeat_stats_read_does_not_rescan_edges(tmp_path: Path, traced: list[str], filters: dict[str, Any]) -> None:
    store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    store.save_graph(_graph("acme", "scan-1", 5))

    first = store.snapshot_stats(tenant_id="acme", scan_id="scan-1", **filters)
    assert _edge_scans(traced) > 0
    traced.clear()
    second = store.snapshot_stats(tenant_id="acme", scan_id="scan-1", **filters)

    assert second == first
    assert _edge_scans(traced) == 0


def test_rewritten_snapshot_is_never_served_stale(tmp_path: Path) -> None:
    store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    store.save_graph(_graph("acme", "scan-1", 5))
    assert store.snapshot_stats(tenant_id="acme", scan_id="scan-1")["relationship_types"] == {"depends_on": 5}

    store.save_graph(_graph("acme", "scan-1", 8))

    stats = store.snapshot_stats(tenant_id="acme", scan_id="scan-1")
    assert stats["relationship_types"] == {"depends_on": 8}
    assert stats["total_nodes"] == 9


def test_tenants_sharing_a_scan_id_keep_their_own_stats(tmp_path: Path) -> None:
    store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    store.save_graph(_graph("acme", "scan-1", 3))
    store.save_graph(_graph("globex", "scan-1", 7))

    assert store.snapshot_stats(tenant_id="acme", scan_id="scan-1")["relationship_types"] == {"depends_on": 3}
    assert store.snapshot_stats(tenant_id="globex", scan_id="scan-1")["relationship_types"] == {"depends_on": 7}
    assert store.snapshot_stats(tenant_id="acme", scan_id="scan-1")["total_nodes"] == 4


def test_cached_stats_are_not_shared_mutable_state(tmp_path: Path) -> None:
    store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    store.save_graph(_graph("acme", "scan-1", 2))
    store.snapshot_stats(tenant_id="acme", scan_id="scan-1")["relationship_types"]["depends_on"] = 999

    assert store.snapshot_stats(tenant_id="acme", scan_id="scan-1")["relationship_types"] == {"depends_on": 2}
