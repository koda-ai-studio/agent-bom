"""Bulk graph saves fold the SQLite write-ahead log back into the main file."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.db.graph_store_write import checkpoint_wal
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

# Small enough for a fast test, large enough that an un-checkpointed WAL is
# visibly bigger than the page-size noise the assertion tolerates.
NODES = 3_000
WAL_CEILING_BYTES = 64 * 1024


def _graph(scan_id: str) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id="default")
    for index in range(NODES):
        graph.add_node(
            UnifiedNode(id=f"n{index}", entity_type=EntityType.PACKAGE, label=f"package-{index}", attributes={"v": "1.%d" % index})
        )
    for index in range(NODES - 1):
        graph.add_edge(UnifiedEdge(source=f"n{index}", target=f"n{index + 1}", relationship=RelationshipType.DEPENDS_ON, traversable=True))
    return graph


def _wal_size(db_path: Path) -> int:
    wal = Path(f"{db_path}-wal")
    return wal.stat().st_size if wal.exists() else 0


def _idle_sibling_connection(db_path: Path) -> sqlite3.Connection:
    """Model the control plane's shared ``control-plane.db``: the job store puts
    the file in WAL mode and keeps an idle connection open, so a graph save
    commits into the WAL and SQLite never runs its close-time checkpoint."""
    sibling = sqlite3.connect(db_path)
    assert sibling.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    sibling.execute("SELECT count(*) FROM sqlite_master").fetchone()
    return sibling


def test_save_graph_leaves_a_truncated_wal(tmp_path: Path) -> None:
    db_path = tmp_path / "graph.db"
    sibling = _idle_sibling_connection(db_path)
    try:
        store = SQLiteGraphStore(str(db_path))
        store.save_graph(_graph("scan-1"))
        assert db_path.stat().st_size > WAL_CEILING_BYTES
        assert _wal_size(db_path) <= WAL_CEILING_BYTES
    finally:
        sibling.close()


def test_save_graph_streaming_leaves_a_truncated_wal(tmp_path: Path) -> None:
    db_path = tmp_path / "graph.db"
    sibling = _idle_sibling_connection(db_path)
    try:
        store = SQLiteGraphStore(str(db_path))
        graph = _graph("scan-2")
        store.save_graph_streaming(scan_id="scan-2", tenant_id="default", nodes=iter(graph.nodes.values()), edges=iter(graph.edges))
        assert _wal_size(db_path) <= WAL_CEILING_BYTES
        assert store.latest_snapshot_id(tenant_id="default") == "scan-2"
    finally:
        sibling.close()


def test_checkpoint_wal_is_best_effort(tmp_path: Path) -> None:
    conn = sqlite3.connect(tmp_path / "plain.db")
    conn.execute("CREATE TABLE t (x)")
    conn.commit()
    assert checkpoint_wal(conn) is False  # rollback journal: nothing to fold
    conn.close()
    assert checkpoint_wal(conn) is False  # closed connection: swallowed, never raised
