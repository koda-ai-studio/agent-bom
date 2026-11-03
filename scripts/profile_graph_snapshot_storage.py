#!/usr/bin/env python3
"""Measure synthetic retained graph storage in a NEW, isolated SQLite directory.

No existing database, credentials, network, or production retention is used.
The original database and all receipts survive the run, including failures.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import platform
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_bom.db.graph_store import load_graph, open_graph_db, purge_expired_graph_snapshots, save_graph  # noqa: E402
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode  # noqa: E402


def _snapshot(index: int, count: int, stamp: str, tenant: str = "storage-probe") -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=f"retained-{index}", tenant_id=tenant, created_at=stamp)
    for i in range(count):
        # Ten percent of attributes change per scan; identity and topology do not.
        attributes = {"description": "synthetic evidence " * 32, "revision": index if i % 10 == 0 else 0}
        graph.add_node(
            UnifiedNode(
                id=f"asset:{i}",
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"Asset {i}",
                attributes=attributes,
                first_seen=stamp,
                last_seen=stamp,
            )
        )
        if i:
            graph.add_edge(
                UnifiedEdge(
                    source=f"asset:{i - 1}", target=f"asset:{i}", relationship=RelationshipType.CONTAINS, first_seen=stamp, last_seen=stamp
                )
            )
    return graph


def _exports(conn: sqlite3.Connection) -> dict[str, str]:
    hashes = {}
    for scan, tenant in conn.execute("SELECT scan_id,tenant_id FROM graph_snapshots ORDER BY tenant_id,scan_id"):
        value = load_graph(conn, scan_id=scan, tenant_id=tenant).to_dict()
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        hashes[f"{tenant}/{scan}"] = hashlib.sha256(encoded).hexdigest()
    return hashes


def _storage(conn: sqlite3.Connection) -> dict[str, Any]:
    result: dict[str, Any] = {
        "database_bytes": conn.execute("PRAGMA page_count").fetchone()[0] * conn.execute("PRAGMA page_size").fetchone()[0],
        "free_pages": conn.execute("PRAGMA freelist_count").fetchone()[0],
        "nodes": conn.execute("SELECT count(*) FROM graph_nodes").fetchone()[0],
        "edges": conn.execute("SELECT count(*) FROM graph_edges").fetchone()[0],
    }
    try:
        result["object_bytes"] = dict(conn.execute("SELECT name,sum(pgsize) FROM dbstat GROUP BY name ORDER BY name"))
    except sqlite3.OperationalError:
        result["object_bytes"] = None  # Some Python SQLite builds omit DBSTAT.
    return result


def _recovery(conn: sqlite3.Connection, output: Path, now: datetime, snapshots: int) -> dict[str, Any]:
    receipt: dict[str, Any] = {}
    before = time.perf_counter()
    with sqlite3.connect(output / "backup.db") as archive:
        conn.backup(archive)
    receipt["backup_seconds"] = time.perf_counter() - before
    before = time.perf_counter()
    with sqlite3.connect(output / "backup.db") as archive, sqlite3.connect(output / "restored.db") as restored:
        archive.backup(restored)
        restored.row_factory = sqlite3.Row
        receipt["restore_seconds"] = time.perf_counter() - before
        receipt["restored_exports"] = _exports(restored)
        # Advance the clock on the restored copy only. Preserve the original
        # history and archive, and use the existing 180-day retention interval.
        cutoff = now - timedelta(minutes=snapshots // 2 + 0.5)
        before = time.perf_counter()
        receipt["purge"] = purge_expired_graph_snapshots(
            restored, retention_days=180, now=cutoff + timedelta(days=180), tenant_id="storage-probe"
        )
        receipt["purge_seconds"] = time.perf_counter() - before
        receipt["after_purge"] = _storage(restored)
        receipt["retained_exports"] = _exports(restored)
        before = time.perf_counter()
        restored.execute("VACUUM")
        receipt["vacuum_seconds"] = time.perf_counter() - before
        receipt["after_vacuum"] = _storage(restored)
        assert _exports(restored) == receipt["retained_exports"], "Vacuum changed exported history"
    return receipt


def profile(output: Path, *, snapshots: int = 10, nodes: int = 1000) -> dict[str, Any]:
    if not 2 <= snapshots <= 200 or not 2 <= nodes <= 5000:
        raise ValueError("Use 2–200 snapshots and 2–5000 nodes per snapshot")
    output.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter()
    now = datetime.now(timezone.utc)
    receipt: dict[str, Any] = {
        "backend": "sqlite",
        "synthetic": True,
        "snapshots": snapshots,
        "nodes_per_snapshot": nodes,
        "attribute_churn_fraction": 0.1,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "sqlite": sqlite3.sqlite_version,
        "storage": [],
    }
    with open_graph_db(output / "source.db") as conn:
        for index in range(snapshots):
            stamp = (now - timedelta(minutes=snapshots - index)).isoformat()
            before = time.perf_counter()
            save_graph(conn, _snapshot(index, nodes, stamp))
            if index in {0, snapshots - 1}:
                receipt["storage"].append({"after_snapshots": index + 1, "save_seconds": time.perf_counter() - before, **_storage(conn)})
        # Same IDs in a second tenant must remain independent during retention.
        save_graph(conn, _snapshot(0, nodes, now.isoformat(), "foreign-probe"))
        before = time.perf_counter()
        receipt["original_exports"] = _exports(conn)
        receipt["full_export_seconds"] = time.perf_counter() - before
        sample = json.dumps(load_graph(conn, tenant_id="storage-probe", scan_id="retained-0").to_dict(), sort_keys=True).encode()
        receipt["one_export_bytes"] = len(sample)
        receipt["one_export_gzip_bytes"] = len(gzip.compress(sample, mtime=0))
        # An estimate only: a production payload key MUST include tenant, schema
        # and immutable bytes. Observation timestamps/membership stay per scan.
        receipt["attribute_bytes"] = conn.execute("SELECT sum(length(CAST(attributes AS BLOB))) FROM graph_nodes").fetchone()[0]
        receipt["tenant_unique_attribute_bytes"] = conn.execute(
            "SELECT sum(length(CAST(attributes AS BLOB))) FROM (SELECT DISTINCT tenant_id,attributes FROM graph_nodes)"
        ).fetchone()[0]
        receipt.update(_recovery(conn, output, now, snapshots))
        assert receipt["original_exports"] == receipt["restored_exports"], "Restored history differs"
        assert all(receipt["original_exports"][key] == value for key, value in receipt["retained_exports"].items())
    receipt["elapsed_seconds"] = time.perf_counter() - started
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New directory; existing paths are refused")
    parser.add_argument("--snapshots", type=int, default=10)
    parser.add_argument("--nodes", type=int, default=1000)
    args = parser.parse_args()
    result = profile(args.output, snapshots=args.snapshots, nodes=args.nodes)
    print(json.dumps({"receipt": str(args.output / "receipt.json"), "seconds": result["elapsed_seconds"]}))


if __name__ == "__main__":
    main()
