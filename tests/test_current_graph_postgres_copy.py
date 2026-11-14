"""A current estate with one PostgreSQL source snapshot is copied as rows, row for row.

Loading the whole source from PostgreSQL into graph objects and writing it back
held the API's interpreter lock for the length of the first build after a large
push, and every graph read in that window waited on it. A single-source view is
the source under the projection's identity, so its rows are streamed from a
server-side cursor into the projection. These tests hold that copy to exactly
what the load-and-rewrite path produces, table by table and row for row, on a
database whose schema comes from the Alembic migrations (JSONB node attributes,
edge evidence and attack-path lists, as deployed). JSONB keeps no key order, so
JSON columns are compared as values; every other column is compared exactly.

Live tier: needs ``AGENT_BOM_POSTGRES_ADMIN_URL`` and ``AGENT_BOM_POSTGRES_URL``.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from agent_bom.api import current_graph_copy
from agent_bom.api.current_graph import CurrentGraphStore
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.store import SQLiteJobStore
from agent_bom.graph import AttackPath, InteractionRisk
from agent_bom.graph.builder import build_unified_graph_from_report
from scripts.generate_graph_benchmark_estate import generate_estate
from tests.test_postgres_migrated_graph_parity import _with_database, migrated_fresh_database  # noqa: F401
from tests.test_postgres_migrated_graph_parity import pytestmark as pytestmark

TENANT = "pg-copy-tenant"
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


@pytest.fixture(autouse=True)
def _bound_tenant():
    """Row-level security admits the copy-tenant's rows only while it is the bound tenant."""
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    token = set_current_tenant(TENANT)
    yield
    reset_current_tenant(token)


def _store():
    from agent_bom.api.postgres_graph import PostgresGraphStore

    return PostgresGraphStore()


def _seed(tmp_path: Path, agents: int) -> SQLiteJobStore:
    jobs = SQLiteJobStore(str(tmp_path / "jobs.db"))
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
    agent_ids = sorted(node.id for node in graph.nodes.values() if node.entity_type.value == "agent")[:2]
    graph.interaction_risks.append(InteractionRisk(pattern="shared-credential", agents=agent_ids, risk_score=7.0, description="shared"))
    _store().save_graph(graph)
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
    return jobs


def _build(jobs: SQLiteJobStore, state: Path, monkeypatch) -> tuple[CurrentGraphStore, str]:
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(state))
    store = CurrentGraphStore(_store(), jobs)
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
                for column, value in record.items():
                    # JSONB keeps no key order, so a JSON column is compared as its value.
                    if isinstance(value, str) and value[:1] in ("{", "["):
                        record[column] = json.loads(value)
                rows.append(json.dumps(record, sort_keys=True, default=str))
            dumped[table] = sorted(rows)
    return dumped


def _spy(monkeypatch) -> list[bool]:
    from agent_bom.api import current_graph_pg_copy

    calls: list[bool] = []
    original = current_graph_pg_copy.copy_postgres_source

    def spy(*args, **kwargs):
        calls.append(result := original(*args, **kwargs))
        return result

    monkeypatch.setattr(current_graph_pg_copy, "copy_postgres_source", spy)
    return calls


@pytest.mark.parametrize("agents", [12, 60])
def test_copied_postgres_projection_matches_the_load_and_rewrite_projection(
    tmp_path,
    monkeypatch,
    migrated_fresh_database,  # noqa: F811
    agents,
) -> None:
    from agent_bom.api import current_graph_pg_copy

    jobs = _seed(tmp_path, agents)
    calls = _spy(monkeypatch)
    copied_store, copied_identity = _build(jobs, tmp_path / "copied", monkeypatch)
    assert calls == [True]

    monkeypatch.setattr(current_graph_pg_copy, "copy_postgres_source", lambda *args, **kwargs: False)
    rewritten_store, rewritten_identity = _build(jobs, tmp_path / "rewritten", monkeypatch)
    assert copied_identity == rewritten_identity
    assert copied_store._cache_path != rewritten_store._cache_path

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
    # The copied projection serves the same graph through the store.
    assert set(copied_store.load_graph(tenant_id=TENANT).nodes) == set(rewritten_store.load_graph(tenant_id=TENANT).nodes)


def _break(database: str, sql: str) -> None:
    import psycopg

    with psycopg.connect(_with_database(os.environ["AGENT_BOM_POSTGRES_ADMIN_URL"], database), autocommit=True) as conn:
        assert conn.execute(sql, (TENANT,)).rowcount, sql


@pytest.mark.parametrize(
    "sql",
    [
        # A source written before agent context existed would change when annotated.
        "UPDATE graph_nodes SET attributes = attributes - 'agent_context' WHERE entity_type = 'agent' AND tenant_id = %s",
        # A source whose stored path index is not the current derivation must be rebuilt.
        "UPDATE graph_snapshots SET analysis_status = (analysis_status::jsonb - 'paths')::text WHERE tenant_id = %s",
        # Agent context written before it stamped its own snapshot on unscanned edges.
        (
            "UPDATE graph_nodes SET attributes = jsonb_set(attributes, '{agent_context,platforms,items,0,source_scan_id}', '\"\"') "
            "WHERE entity_type = 'agent' AND attributes #> '{agent_context,platforms,items,0}' IS NOT NULL AND tenant_id = %s"
        ),
        # A node stored before generated identities were recorded gets a legacy identity on rewrite.
        "UPDATE graph_nodes SET attributes = attributes - '_agent_bom_canonical_id' WHERE entity_type = 'package' AND tenant_id = %s",
    ],
    ids=["no-agent-context", "stale-path-index", "unstamped-agent-context", "unrecorded-identity"],
)
def test_postgres_copy_declines_when_the_source_would_not_equal_the_projection(
    tmp_path,
    monkeypatch,
    migrated_fresh_database,  # noqa: F811
    sql,
) -> None:
    jobs = _seed(tmp_path, 12)
    _break(migrated_fresh_database, sql)
    calls = _spy(monkeypatch)
    store, identity = _build(jobs, tmp_path / "state", monkeypatch)
    assert calls == [False]
    assert _dump(store, identity)["graph_nodes"]


def test_postgres_copy_declines_a_source_revised_after_it_was_resolved(tmp_path, monkeypatch, migrated_fresh_database) -> None:  # noqa: F811
    """A re-save after the build resolved its revision is never copied under the old identity."""
    from agent_bom.api import current_graph_pg_copy

    jobs = _seed(tmp_path, 12)
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    store = CurrentGraphStore(_store(), jobs)
    scan = jobs.list_summary(tenant_id=TENANT)[0]["job_id"]
    _scan, revision = store._graph_store.snapshot_identity(tenant_id=TENANT, scan_id=scan, for_paging=True)
    assert revision
    copied = current_graph_pg_copy.copy_postgres_source(
        store,
        tenant=TENANT,
        source_scan=scan,
        expected_revision="a-revision-that-moved",
        identity="current-estate:moved",
        created_at="2026-11-13T00:00:00Z",
        write_generation="moved",
        evidence_manifest_sha256="sha256:moved",
    )
    assert copied is False
    with sqlite3.connect(store._cache_path) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        if "graph_nodes" in tables:
            assert not conn.execute("SELECT 1 FROM graph_nodes WHERE scan_id = 'current-estate:moved'").fetchone()


def test_two_postgres_sources_are_never_copied(tmp_path, monkeypatch, migrated_fresh_database) -> None:  # noqa: F811
    jobs = _seed(tmp_path, 12)
    calls = _spy(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    store = CurrentGraphStore(_store(), jobs)
    assert not current_graph_copy.copy_current_projection(
        store, TENANT, "identity", "", (("scan-a", "rev-a"), ("scan-b", "rev-b")), "digest"
    )
    assert calls == []


_CRASHING_CHILD = """
import os

from agent_bom.api import current_graph_pg_copy, current_graph_pg_copy_worker

real = current_graph_pg_copy._copy_table


def crash_after_first_table(*args, **kwargs):
    real(*args, **kwargs)
    os._exit(9)


current_graph_pg_copy._copy_table = crash_after_first_table
raise SystemExit(current_graph_pg_copy_worker.main())
"""


def test_a_child_that_dies_mid_copy_promotes_nothing_and_the_build_rebuilds(
    tmp_path,
    monkeypatch,
    migrated_fresh_database,  # noqa: F811
) -> None:
    from agent_bom.api import current_graph_pg_copy_child

    jobs = _seed(tmp_path, 12)
    package = tmp_path / "crash_children"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "crasher.py").write_text(_CRASHING_CHILD)
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(p for p in (str(tmp_path), os.environ.get("PYTHONPATH", "")) if p))
    monkeypatch.setattr(current_graph_pg_copy_child, "CHILD_MODULE", "crash_children.crasher")
    calls = _spy(monkeypatch)
    state = tmp_path / "state"
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(state))
    store = CurrentGraphStore(_store(), jobs)
    identity_before = None
    # The child wrote graph_nodes in its open transaction, then died: none of it may be visible.
    original_rows = current_graph_pg_copy_child.copy_in_child

    def checked(cache_path, **kwargs):
        nonlocal identity_before
        result = original_rows(cache_path, **kwargs)
        identity_before = kwargs["identity"]
        with sqlite3.connect(cache_path) as conn:
            assert not conn.execute("SELECT 1 FROM graph_nodes WHERE scan_id = ?", (kwargs["identity"],)).fetchone()
        return result

    monkeypatch.setattr(current_graph_pg_copy_child, "copy_in_child", checked)
    assert store.prepare_current(TENANT, seconds=120)
    assert calls == [False]
    # The rebuild then produced the same projection the copy would have.
    identity = store._cache[TENANT][2]
    assert identity == identity_before
    assert _dump(store, identity)["graph_nodes"]
