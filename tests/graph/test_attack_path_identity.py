"""Persisted fusion paths keep one row per route occurrence, with their findings."""

from __future__ import annotations

import json
import sqlite3

from agent_bom.db.graph_store import load_graph, open_graph_db, save_graph
from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.snapshot_paths import occurrence_path_keys, path_identity


def _same_endpoints_graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="s1", tenant_id="t1")
    for node_id, kind in (("agent:a", EntityType.AGENT), ("server:s", EntityType.SERVER), ("vuln:CVE-1", EntityType.VULNERABILITY)):
        graph.add_node(UnifiedNode(id=node_id, entity_type=kind, label=node_id))
    graph.add_edge(UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES))
    graph.add_edge(UnifiedEdge(source="server:s", target="vuln:CVE-1", relationship=RelationshipType.VULNERABLE_TO))
    graph.attack_paths.append(
        AttackPath(
            source="agent:a",
            target="vuln:CVE-1",
            hops=["agent:a", "server:s", "vuln:CVE-1"],
            edges=["uses", "vulnerable_to"],
            composite_risk=50,
            vuln_ids=["CVE-1"],
            finding_ids=["F1"],
        )
    )
    graph.attack_paths.append(
        AttackPath(
            source="agent:a",
            target="vuln:CVE-1",
            hops=["agent:a", "vuln:CVE-1"],
            edges=["vulnerable_to"],
            composite_risk=40,
            vuln_ids=["CVE-1"],
            finding_ids=["F2"],
        )
    )
    return graph


def test_distinct_routes_between_same_endpoints_survive_save_and_load(tmp_path) -> None:
    with open_graph_db(tmp_path / "g.db") as conn:
        save_graph(conn, _same_endpoints_graph())
        back = load_graph(conn, tenant_id="t1", scan_id="s1")

    assert [(path.hops, path.composite_risk, path.finding_ids) for path in back.attack_paths] == [
        (["agent:a", "server:s", "vuln:CVE-1"], 50, ["F1"]),
        (["agent:a", "vuln:CVE-1"], 40, ["F2"]),
    ]


def test_repeated_identical_route_keeps_every_occurrence(tmp_path) -> None:
    graph = _same_endpoints_graph()
    graph.attack_paths.append(AttackPath.from_dict(graph.attack_paths[0].to_dict() | {"composite_risk": 30}))
    with open_graph_db(tmp_path / "g.db") as conn:
        save_graph(conn, graph)
        back = load_graph(conn, tenant_id="t1", scan_id="s1")
        keys = [row[0] for row in conn.execute("SELECT path_key FROM attack_paths ORDER BY composite_risk DESC")]

    assert [path.composite_risk for path in back.attack_paths] == [50, 40, 30]
    first = path_identity(graph.attack_paths[0])
    assert keys == [first, path_identity(graph.attack_paths[1]), f"{first}:1"]


def test_occurrence_keys_suffix_only_repeats() -> None:
    graph = _same_endpoints_graph()
    a, b = graph.attack_paths
    keys = [key for key, _ in occurrence_path_keys([a, b, a, a])]
    assert keys == [path_identity(a), path_identity(b), f"{path_identity(a)}:1", f"{path_identity(a)}:2"]


_LEGACY_ATTACK_PATHS = """
CREATE TABLE attack_paths (
    source_node TEXT NOT NULL, target_node TEXT NOT NULL, hop_count INTEGER DEFAULT 0,
    composite_risk REAL DEFAULT 0.0, path_nodes TEXT DEFAULT '[]', path_edges TEXT DEFAULT '[]',
    credential_exposure TEXT DEFAULT '[]', vuln_ids TEXT DEFAULT '[]', scan_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default', computed_at TEXT NOT NULL,
    PRIMARY KEY (source_node, target_node, scan_id, tenant_id)
)
"""


def test_legacy_store_upgrades_to_occurrence_identity(tmp_path) -> None:
    db = tmp_path / "legacy.db"
    hops, edges = ["agent:a", "server:s", "vuln:CVE-1"], ["uses", "vulnerable_to"]
    with sqlite3.connect(db) as raw:
        raw.execute(_LEGACY_ATTACK_PATHS)
        raw.execute(
            "INSERT INTO attack_paths (source_node, target_node, hop_count, composite_risk, path_nodes, path_edges,"
            " scan_id, tenant_id, computed_at)"
            " VALUES ('agent:a', 'vuln:CVE-1', 3, 70.0, ?, ?, 's0', 't1', '2026-01-01T00:00:00Z')",
            (json.dumps(hops), json.dumps(edges)),
        )

    with open_graph_db(db) as conn:
        row = conn.execute("SELECT path_key, finding_ids, composite_risk FROM attack_paths").fetchone()
        pk = [r["name"] for r in sorted(conn.execute("PRAGMA table_info(attack_paths)").fetchall(), key=lambda r: r["pk"]) if r["pk"]]
        save_graph(conn, _same_endpoints_graph())
        back = load_graph(conn, tenant_id="t1", scan_id="s1")

    assert tuple(row) == (path_identity(AttackPath(source="agent:a", target="vuln:CVE-1", hops=hops, edges=edges)), "[]", 70.0)
    assert pk == ["tenant_id", "scan_id", "path_key"]
    assert len(back.attack_paths) == 2
    # Reopening an upgraded store is a no-op.
    with open_graph_db(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM attack_paths").fetchone()[0] == 3
