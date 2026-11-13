"""A current estate with one source snapshot is copied in SQL, row for row.

Loading the whole source into Python and writing it back was about 90% of a
cold current-graph build at 5,000 agents. When the view has exactly one source
snapshot on SQLite, the projection is the source with the projection's
identity, so it is copied with INSERT ... SELECT. These tests hold the copy to
exactly what the load-and-rewrite path produces, table by table.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from agent_bom.api import current_graph_copy
from agent_bom.api.current_graph import CurrentGraphStore
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.store import SQLiteJobStore
from agent_bom.graph import AttackPath, InteractionRisk
from agent_bom.graph.builder import build_unified_graph_from_report
from scripts.generate_graph_benchmark_estate import generate_estate

TENANT = "copy-tenant"
_TABLES = (
    "graph_nodes",
    "graph_edges",
    "graph_node_aliases",
    "graph_node_search",
    "attack_paths",
    "graph_attack_paths",
    "interaction_risks",
    "graph_snapshots",
)
_JSON_SNAPSHOT_COLUMNS = {"risk_summary", "node_type_counts", "analysis_status"}


def _seed(tmp_path: Path, monkeypatch, agents: int) -> tuple[SQLiteJobStore, Path]:
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    jobs = SQLiteJobStore(str(tmp_path / "jobs.db"))
    source = tmp_path / "source.db"
    graphs = SQLiteGraphStore(source)
    report, _summary = generate_estate(agents=agents, seed=2145, vulnerable_package_rate=0.08)
    report["scan_run"] = {"outcome": "complete"}
    graph = build_unified_graph_from_report(report, tenant_id=TENANT, scan_id=report["scan_id"])
    # Legacy attack paths and interaction risks, which the generated estate has none of.
    for index, edge in enumerate(graph.edges[:3]):
        graph.attack_paths.append(
            AttackPath(
                source=edge.source,
                target=edge.target,
                hops=[edge.source, edge.target],
                edges=[edge.relationship.value],
                composite_risk=5.0 + index,
                summary=f"path {index}",
                vuln_ids=[f"CVE-2026-{index:04d}"],
            )
        )
    agents = sorted(node.id for node in graph.nodes.values() if node.entity_type.value == "agent")[:2]
    graph.interaction_risks.append(InteractionRisk(pattern="shared-credential", agents=agents, risk_score=7.0, description="shared"))
    graphs.save_graph(graph)
    jobs.put(
        ScanJob(
            job_id=report["scan_id"],
            tenant_id=TENANT,
            status=JobStatus.DONE,
            created_at=report["generated_at"],
            completed_at=report["generated_at"],
            request=ScanRequest(),
            target={"path": "copy-repository"},
            result=report,
        )
    )
    return jobs, source


def _clone(source: Path, target: Path) -> Path:
    with sqlite3.connect(source) as src, sqlite3.connect(target) as dst:
        src.backup(dst)
    return target


def _build(jobs: SQLiteJobStore, path: Path) -> tuple[CurrentGraphStore, str]:
    store = CurrentGraphStore(SQLiteGraphStore(path), jobs)
    assert store.prepare_current(TENANT, seconds=120)
    return store, store._cache[TENANT][2]


def _dump(store: CurrentGraphStore, identity: str) -> dict[str, list[str]]:
    dumped: dict[str, list[str]] = {}
    with sqlite3.connect(store._cache_path) as conn:
        conn.row_factory = sqlite3.Row
        for table in _TABLES:
            rows = []
            for row in conn.execute(f"SELECT * FROM {table} WHERE tenant_id = ? AND scan_id = ?", (TENANT, identity)):  # nosec B608 - test-local table list
                record = dict(row)
                record.pop("rowid", None)
                if table == "graph_snapshots":
                    for column in _JSON_SNAPSHOT_COLUMNS:
                        if record.get(column) is not None:
                            record[column] = json.loads(record[column])
                rows.append(json.dumps(record, sort_keys=True, default=str))
            dumped[table] = sorted(rows)
    return dumped


@pytest.mark.parametrize("agents", [12, 60])
def test_copied_projection_matches_the_load_and_rewrite_projection(tmp_path, monkeypatch, agents) -> None:
    jobs, source = _seed(tmp_path, monkeypatch, agents)
    rewrite_source = _clone(source, tmp_path / "rewrite.db")
    calls: list[bool] = []
    original = current_graph_copy.copy_single_source

    def spy(*args, **kwargs):
        calls.append(result := original(*args, **kwargs))
        return result

    monkeypatch.setattr(current_graph_copy, "copy_single_source", spy)
    copied_store, copied_identity = _build(jobs, source)
    assert calls == [True]

    monkeypatch.setattr(current_graph_copy, "copy_single_source", lambda *args, **kwargs: False)
    rewritten_store, rewritten_identity = _build(jobs, rewrite_source)
    assert copied_identity == rewritten_identity

    copied, rewritten = _dump(copied_store, copied_identity), _dump(rewritten_store, rewritten_identity)
    for table in (
        "graph_nodes",
        "graph_edges",
        "graph_node_search",
        "attack_paths",
        "graph_attack_paths",
        "interaction_risks",
        "graph_snapshots",
    ):
        assert copied[table], table
    for table in _TABLES:
        assert copied[table] == rewritten[table], table


def _break(source: Path, sql: str) -> None:
    with sqlite3.connect(source) as conn:
        conn.execute(sql, (TENANT,))


@pytest.mark.parametrize(
    "sql",
    [
        # A source written before agent context existed would change when annotated.
        "UPDATE graph_nodes SET attributes = json_remove(attributes, '$.agent_context') WHERE entity_type = 'agent' AND tenant_id = ?",
        # A source whose stored path index is not the current derivation must be rebuilt.
        "UPDATE graph_snapshots SET analysis_status = json_remove(analysis_status, '$.paths') WHERE tenant_id = ?",
        # Agent context written before it stamped its own snapshot on unscanned edges.
        "UPDATE graph_nodes SET attributes = json_set(attributes, '$.agent_context.platforms.items[0].source_scan_id', '') "
        "WHERE entity_type = 'agent' AND json_extract(attributes, '$.agent_context.platforms.items[0]') IS NOT NULL AND tenant_id = ?",
    ],
    ids=["no-agent-context", "stale-path-index", "unstamped-agent-context"],
)
def test_copy_declines_when_the_source_would_not_equal_the_projection(tmp_path, monkeypatch, sql) -> None:
    jobs, source = _seed(tmp_path, monkeypatch, 12)
    _break(source, sql)
    calls: list[bool] = []
    original = current_graph_copy.copy_single_source

    def spy(*args, **kwargs):
        calls.append(result := original(*args, **kwargs))
        return result

    monkeypatch.setattr(current_graph_copy, "copy_single_source", spy)
    store, identity = _build(jobs, source)
    assert calls == [False]
    assert _dump(store, identity)["graph_nodes"]


def test_two_sources_are_never_copied(tmp_path, monkeypatch) -> None:
    jobs, source = _seed(tmp_path, monkeypatch, 12)
    calls: list[bool] = []
    monkeypatch.setattr(current_graph_copy, "copy_single_source", lambda *args, **kwargs: calls.append(True) or True)
    store = CurrentGraphStore(SQLiteGraphStore(source), jobs)
    assert not current_graph_copy.copy_current_projection(
        store, TENANT, "identity", "", (("scan-a", "rev-a"), ("scan-b", "rev-b")), "digest"
    )
    assert calls == []
    shutil.rmtree(tmp_path / "state", ignore_errors=True)
