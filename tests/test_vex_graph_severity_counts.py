"""Operator-VEX-suppressed findings stay out of graph severity counts on every path.

``finding_summary`` already excludes them; the graph's ``stats()``, the
materialised snapshot counts and the live SQL GROUP BY must agree with it.
"""

from __future__ import annotations

from collections import Counter

from agent_bom.finding import blast_radius_to_finding
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.severity_floor import counts_as_finding_node
from agent_bom.output import to_json
from agent_bom.vex import apply_vex
from tests.test_vex_operator_suppression import _report, _vex


def _suppressed_graph(tmp_path, *, source: str = "operator"):
    report = _report()
    assert apply_vex(report, _vex(tmp_path), source=source) >= 1
    report.findings = [blast_radius_to_finding(br) for br in report.blast_radii]
    doc = to_json(report)
    graph = build_unified_graph_from_report(doc, scan_id="vex-scan", tenant_id="tenant-vex")
    return doc, graph


def _active_high(doc) -> int:
    return int(doc["finding_summary"]["by_severity"].get("high", 0))


def test_in_memory_stats_exclude_operator_vex_suppressed(tmp_path):
    doc, graph = _suppressed_graph(tmp_path)
    assert doc["finding_summary"]["suppressed"] == 1
    assert graph.stats()["severity_counts"].get("high", 0) == _active_high(doc) == 1
    counted = Counter(n.severity for n in graph.nodes.values() if n.severity and counts_as_finding_node(n))
    assert counted.get("high", 0) == 1


def test_discovered_vex_stays_counted(tmp_path):
    doc, graph = _suppressed_graph(tmp_path, source="discovered")
    assert doc["finding_summary"].get("suppressed", 0) == 0
    assert graph.stats()["severity_counts"].get("high", 0) == 2


def test_sqlite_snapshot_and_live_counts_exclude_suppressed(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    _doc, graph = _suppressed_graph(tmp_path)
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(graph)
    cached = store.snapshot_stats(tenant_id="tenant-vex", scan_id="vex-scan")
    assert cached["severity_counts"].get("high", 0) == 1
    live = store.snapshot_stats(tenant_id="tenant-vex", scan_id="vex-scan", entity_types={"vulnerability"})
    assert live["severity_counts"].get("high", 0) == 1


def test_cli_store_snapshot_counts_exclude_suppressed(tmp_path):
    import json

    from agent_bom.db import graph_store as cli_store

    _doc, graph = _suppressed_graph(tmp_path)
    with cli_store.open_graph_db(tmp_path / "cli-graph.db") as conn:
        cli_store.save_graph(conn, graph)
        row = conn.execute("SELECT risk_summary FROM graph_snapshots WHERE scan_id = ?", ("vex-scan",)).fetchone()

    assert json.loads(row[0]).get("high", 0) == 1
