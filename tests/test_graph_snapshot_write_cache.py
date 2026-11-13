"""A graph snapshot write runs with a page cache sized for its index inserts.

graph_edges carries about a dozen indexes. On SQLite's default 2 MiB cache a
5,000-agent snapshot (170,330 nodes, 229,197 edges) thrashed the cache on
every random-key index insert: the cold current-graph read took about 508 s.
With 64 MiB for the write it took about 60 s. The larger cache is held only
for the write, so idle connections keep the default footprint.
"""

from __future__ import annotations

import sqlite3

from agent_bom.db import graph_store
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedNode


def _connect(tmp_path) -> sqlite3.Connection:
    conn = sqlite3.connect(tmp_path / "graph.db")
    conn.row_factory = sqlite3.Row
    graph_store._init_db(conn)
    return conn


def _cache_kib(conn: sqlite3.Connection) -> int:
    value = int(conn.execute("PRAGMA cache_size").fetchone()[0])
    # Negative values are KiB; positive values are pages.
    return -value if value < 0 else value * int(conn.execute("PRAGMA page_size").fetchone()[0]) // 1024


def test_snapshot_write_holds_a_large_page_cache_and_restores_it(tmp_path) -> None:
    conn = _connect(tmp_path)
    before = conn.execute("PRAGMA cache_size").fetchone()[0]
    seen: list[int] = []

    def nodes():
        for index in range(3):
            seen.append(_cache_kib(conn))
            yield UnifiedNode(id=f"agent:{index}", entity_type=EntityType.AGENT, label=f"Agent {index}")

    counts = graph_store.save_graph_streaming(
        conn,
        scan_id="scan-1",
        tenant_id="tenant-a",
        nodes=nodes(),
        edges=[UnifiedEdge(source="agent:0", target="agent:1", relationship=RelationshipType.USES)],
    )
    assert counts == {"nodes": 3, "edges": 1}
    assert seen and min(seen) >= 64 * 1024
    assert conn.execute("PRAGMA cache_size").fetchone()[0] == before


def test_failed_snapshot_write_still_restores_the_cache(tmp_path) -> None:
    conn = _connect(tmp_path)
    before = conn.execute("PRAGMA cache_size").fetchone()[0]

    def broken():
        yield UnifiedNode(id="agent:0", entity_type=EntityType.AGENT, label="Agent")
        raise RuntimeError("producer failed")

    try:
        graph_store.save_graph_streaming(conn, scan_id="scan-1", tenant_id="tenant-a", nodes=broken(), edges=[])
    except RuntimeError:
        pass
    else:  # pragma: no cover - the producer always raises
        raise AssertionError("the producer error must surface")
    conn.rollback()
    assert conn.execute("PRAGMA cache_size").fetchone()[0] == before


def test_whole_snapshot_load_holds_the_large_cache_and_restores_it(tmp_path, monkeypatch) -> None:
    conn = _connect(tmp_path)
    graph_store.save_graph_streaming(
        conn,
        scan_id="scan-1",
        tenant_id="tenant-a",
        nodes=[UnifiedNode(id="agent:0", entity_type=EntityType.AGENT, label="Agent")],
        edges=[],
    )
    before = conn.execute("PRAGMA cache_size").fetchone()[0]
    seen: list[int] = []
    original = graph_store.UnifiedNode.from_stored

    def spy(*args, **kwargs):
        seen.append(_cache_kib(conn))
        return original(*args, **kwargs)

    monkeypatch.setattr(graph_store.UnifiedNode, "from_stored", spy)
    graph = graph_store.load_graph(conn, tenant_id="tenant-a", scan_id="scan-1")
    assert set(graph.nodes) == {"agent:0"}
    assert seen and min(seen) >= 64 * 1024
    assert conn.execute("PRAGMA cache_size").fetchone()[0] == before
