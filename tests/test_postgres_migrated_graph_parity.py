"""Migration-owned Postgres graph round-trip against a real, freshly migrated db.

Opt-in live tier: proves the graph store works on a database whose schema was
created ONLY by Alembic (``alembic upgrade head``) — the store's dev-mode
bootstrap DDL never runs because ``AGENT_BOM_POSTGRES_URL`` is set. Regression
for the P1 where ``attack_paths.summary`` / ``tool_exposure`` /
``technique_mappings`` / reachability evidence existed only in the bootstrap DDL, so every
migration-owned deployment 500'd on the first ``/v1/graph`` read.

Requires two opt-in env vars (skipped otherwise):
- ``AGENT_BOM_POSTGRES_ADMIN_URL`` — a CREATEDB-capable role used to create /
  drop the throwaway database and run Alembic (never used by the app).
- ``AGENT_BOM_POSTGRES_URL`` — the app-role URL template (its database path is
  rewritten to the throwaway database).
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not (os.environ.get("AGENT_BOM_POSTGRES_ADMIN_URL") and os.environ.get("AGENT_BOM_POSTGRES_URL")),
    reason="AGENT_BOM_POSTGRES_ADMIN_URL + AGENT_BOM_POSTGRES_URL are required for live migration parity tests",
)

REPO_ROOT = Path(__file__).parent.parent
ALEMBIC_DIR = REPO_ROOT / "deploy" / "supabase" / "postgres"


def _with_database(url: str, database: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


def _sqlalchemy_url(url: str) -> str:
    """Force the psycopg3 SQLAlchemy driver (plain postgresql:// selects psycopg2)."""
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


@pytest.fixture()
def migrated_fresh_database(monkeypatch, request):
    """Create a throwaway database, migrate it to Alembic head, point the app at it."""
    import psycopg

    admin_url = os.environ["AGENT_BOM_POSTGRES_ADMIN_URL"]
    app_url = os.environ["AGENT_BOM_POSTGRES_URL"]
    database = f"abom_mig_parity_{uuid4().hex[:12]}"

    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{database}"')
    try:
        from alembic import command
        from alembic.config import Config

        cfg = Config(str(ALEMBIC_DIR / "alembic.ini"))
        cfg.set_main_option("script_location", str(ALEMBIC_DIR / "alembic"))
        monkeypatch.setenv("ALEMBIC_DATABASE_URL", _sqlalchemy_url(_with_database(admin_url, database)))
        command.upgrade(cfg, getattr(request, "param", "head"))

        from agent_bom.api import postgres_common

        monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", _with_database(app_url, database))
        postgres_common.reset_pool()
        yield database
        pool = postgres_common._pool
        if pool is not None:
            pool.close()
        postgres_common.reset_pool()
    finally:
        with psycopg.connect(admin_url, autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)')


def test_attack_paths_round_trip_on_migration_owned_schema(migrated_fresh_database):
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore
    from agent_bom.graph import AttackPath
    from agent_bom.graph.container import TechniqueMapping

    store = PostgresGraphStore()
    path = AttackPath(
        source="agent:web",
        target="secret:prod-db",
        hops=["agent:web", "secret:prod-db"],
        edges=["agent:web->secret:prod-db"],
        composite_risk=8.5,
        summary="internet-facing agent reaches a production secret",
        credential_exposure=["prod-db-password"],
        tool_exposure=["shell-tool"],
        vuln_ids=["CVE-2026-0001"],
        reachability="confirmed",
        reachability_basis=["graph_path", "runtime_observed"],
        technique_mappings=[TechniqueMapping(hop_index=0, technique_id="T1078", technique_name="Valid Accounts", confidence=0.6)],
    )
    token = set_current_tenant("default")
    try:
        store.save_graph_streaming(
            scan_id="mig-parity-scan",
            tenant_id="default",
            nodes=[],
            edges=[],
            attack_paths=[path],
        )
        loaded = store.attack_paths_for_sources(tenant_id="default", scan_id="mig-parity-scan", source_ids={"agent:web"})
    finally:
        reset_current_tenant(token)

    assert len(loaded) == 1
    got = loaded[0]
    assert got.summary == "internet-facing agent reaches a production secret"
    assert got.tool_exposure == ["shell-tool"]
    assert got.credential_exposure == ["prod-db-password"]
    assert got.vuln_ids == ["CVE-2026-0001"]
    assert got.reachability == "confirmed"
    assert got.reachability_basis == ["graph_path", "runtime_observed"]
    assert [m.technique_id for m in got.technique_mappings] == ["T1078"]


def test_graph_correlation_round_trip_on_migration_owned_schema(migrated_fresh_database):
    from agent_bom.api.postgres_graph import PostgresGraphStore
    from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode
    from agent_bom.graph.correlation import (
        CorrelationRunStatus,
        GraphCorrelationRun,
        correlation_graph_digest,
        correlation_manifest_digest,
    )

    store = PostgresGraphStore()
    run = GraphCorrelationRun(
        correlation_id="corr-migration-parity",
        tenant_id="default",
        idempotency_key="idem-migration-parity",
        name="migration parity",
        status=CorrelationRunStatus.PENDING,
        max_age_hours=168,
        allow_stale=False,
        input_manifest=[{"scan_id": "scan-a"}, {"scan_id": "scan-b"}],
        created_at="2026-08-30T00:00:00+00:00",
    )

    created, was_created = store.create_correlation_run(run)
    replayed, replay_created = store.create_correlation_run(run)
    running = store.update_correlation_run(
        tenant_id="default",
        correlation_id=run.correlation_id,
        status=CorrelationRunStatus.RUNNING,
        started_at="2026-08-30T00:01:00+00:00",
    )
    output = UnifiedGraph(
        scan_id=run.correlation_id,
        tenant_id="default",
        created_at="2026-08-30T00:02:00+00:00",
    )
    output.add_node(UnifiedNode(id="agent:migration", entity_type=EntityType.AGENT, label="migration"))
    result_manifest = {
        "schema_version": "agent-bom.graph-correlation-manifest/v1",
        "correlation_id": run.correlation_id,
        "tenant_id": "default",
        "output": {
            "scan_id": run.correlation_id,
            "node_count": 1,
            "edge_count": 0,
            "graph_digest_sha256": correlation_graph_digest(output),
        },
    }
    manifest_sha256 = correlation_manifest_digest(result_manifest)
    complete = store.complete_correlation_run(
        output,
        result_manifest=result_manifest,
        manifest_sha256=manifest_sha256,
        completed_at="2026-08-30T00:02:00+00:00",
    )
    snapshots = store.snapshots_by_ids(tenant_id="default", scan_ids={run.correlation_id})

    assert was_created is True
    assert replay_created is False
    assert replayed.correlation_id == created.correlation_id
    assert running.status is CorrelationRunStatus.RUNNING
    assert complete.status is CorrelationRunStatus.COMPLETE
    assert complete.output_scan_id == run.correlation_id
    assert complete.manifest_sha256 == manifest_sha256
    assert complete.result_manifest == result_manifest
    assert snapshots[0]["snapshot_kind"] == "correlation"
    assert snapshots[0]["evidence_manifest_sha256"] == manifest_sha256


def test_audit_fork_guard_unique_index_present_after_migrate_to_head(migrated_fresh_database):
    """The hash-chain fork guard must exist in a schema built ONLY by Alembic.

    ``PostgresAuditLog._ensure_fork_guard_index`` never runs when Postgres is
    authoritative (``_init_tables`` early-returns), so a migration that dropped
    ``UNIQUE (team_id, prev_signature)`` (#4232) would leave concurrent appends
    across ``uvicorn --workers N`` able to fork the chain with nothing to catch
    it. Assert the index exists, is UNIQUE, and covers exactly the head key.
    """
    import psycopg

    from agent_bom.api.postgres_common import resolve_postgres_secret, resolve_postgres_url

    with psycopg.connect(resolve_postgres_url(), password=resolve_postgres_secret()) as conn:
        row = conn.execute(
            "SELECT indexdef FROM pg_indexes WHERE tablename = 'audit_log' AND indexname = 'audit_log_team_prevsig_uniq'"
        ).fetchone()

    assert row is not None, "audit_log fork-guard index missing from migration-owned schema"
    indexdef = row[0]
    assert "UNIQUE INDEX" in indexdef
    assert "team_id" in indexdef and "prev_signature" in indexdef


@pytest.mark.parametrize("migrated_fresh_database", ["20260923_02"], indirect=True)
def test_comparable_trends_round_trip_and_tenant_isolation(migrated_fresh_database, tmp_path):
    """Migration-created metadata survives retries with the same SQLite result."""
    import psycopg
    from alembic import command
    from alembic.config import Config

    from agent_bom.api.postgres_audit import PostgresTrendStore
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.baseline import SQLiteTrendStore, TrendPoint

    cfg = Config(str(ALEMBIC_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(ALEMBIC_DIR / "alembic"))
    # Seed the legacy schema directly: newer ledger migrations deliberately
    # reject downgrade because rollback requires restoring a compatible backup.
    admin_url = _with_database(os.environ["AGENT_BOM_POSTGRES_ADMIN_URL"], migrated_fresh_database)
    with psycopg.connect(admin_url) as conn:
        conn.execute(
            "INSERT INTO trend_history (timestamp, team_id, total_vulns, scan_id) VALUES (%s, %s, %s, %s)",
            ("2026-09-01T00:00:00Z", "legacy", 1, "legacy-scan"),
        )
    command.upgrade(cfg, "head")
    postgres = PostgresTrendStore()
    assert postgres.get_history(tenant_id="legacy")[0].comparison_metadata == {}
    sqlite = SQLiteTrendStore(str(tmp_path / "trends.db"))
    for tenant in ("trend-a", "trend-b"):
        token = set_current_tenant("worker-default")
        try:
            point = TrendPoint(
                timestamp="2026-09-24T12:00:00Z",
                total_vulns=1,
                critical=0,
                high=1,
                medium=0,
                low=0,
                posture_score=90,
                posture_grade="A",
                tenant_id=tenant,
                scan_id="same-scan",
                comparison_metadata={
                    "scope_id": "repo:a",
                    "measurement_version": 1,
                    "collection_coverage": "complete",
                    "observations": [{"keys": [tenant]}],
                },
            )
            for store in (postgres, sqlite):
                store.record(point)
                store.record(point)
        finally:
            reset_current_tenant(token)
    for tenant in ("trend-a", "trend-b"):
        pg_rows = postgres.get_history(tenant_id=tenant)
        sql_rows = sqlite.get_history(tenant_id=tenant)
        assert len(pg_rows) == len(sql_rows) == 1
        assert pg_rows[0] == sql_rows[0]
    assert postgres.get_history(tenant_id="other") == []
    for index in range(9):
        oversized = TrendPoint(
            timestamp=f"2026-09-{index + 1:02d}T00:00:00Z",
            total_vulns=1,
            critical=0,
            high=1,
            medium=0,
            low=0,
            posture_score=90,
            posture_grade="A",
            tenant_id="budget",
            scan_id=str(index),
            comparison_metadata={"padding": "x" * (2 * 1024 * 1024)},
        )
        postgres.record(oversized)
    bounded = postgres.get_history(tenant_id="budget")
    assert bounded[-1].comparison_metadata == {"history_processing_limit": True}
    assert sum(len(str(row.comparison_metadata)) for row in bounded) < 16 * 1024 * 1024


def test_ambiguous_alias_replay_keeps_nodes_without_inventing_identity(migrated_fresh_database):
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore
    from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode

    tenant = "ambiguous-alias-replay"
    token = set_current_tenant(tenant)
    store = PostgresGraphStore()
    try:
        for scan, ids in (("one", ["dataset:a", "dataset:b"]), ("two", ["dataset:b", "dataset:a"])):
            graph = UnifiedGraph(tenant_id=tenant, scan_id=scan)
            for node_id in ids:
                graph.add_node(
                    UnifiedNode(
                        id=node_id, entity_type=EntityType.DATASET, label="data", attributes={"identity": {"aliases": ["dataset:data"]}}
                    )
                )
            store.save_graph(graph)
            store.save_graph(graph)
            assert store.resolve_node_aliases(tenant_id=tenant, scan_id=scan, node_ids=["dataset:data"]) == {}
            assert set(store.load_graph(tenant_id=tenant, scan_id=scan).nodes) == set(ids)
        assert store.resolve_node_aliases(tenant_id=tenant, node_ids=["dataset:data"]) == {}
        assert store.resolve_node_aliases(tenant_id="other", node_ids=["dataset:data"]) == {}
    finally:
        store.delete_tenant(tenant_id=tenant)
        reset_current_tenant(token)


def test_lifecycle_projection_round_trip_with_forced_tenant_isolation(migrated_fresh_database):
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore
    from agent_bom.graph import UnifiedGraph
    from agent_bom.graph.lifecycle import agent_lifecycle_view

    package = {"name": "shared", "version": "1.0", "ecosystem": "npm"}
    view = agent_lifecycle_view(
        {
            "name": "fixture",
            "agent_type": "custom",
            "mcp_servers": [
                {"name": "same", "url": "https://one.example/mcp", "packages": [package]},
                {"name": "same", "url": "https://two.example/mcp", "packages": [package]},
            ],
        },
        tenant_id="lifecycle-tenant",
    )
    graph = UnifiedGraph.from_dict(view["graph"])
    graph.scan_id = "lifecycle-replay"
    store = PostgresGraphStore()
    token = set_current_tenant("lifecycle-tenant")
    try:
        store.save_graph(graph)
        loaded = store.load_graph(tenant_id="lifecycle-tenant", scan_id=graph.scan_id)
        assert set(loaded.nodes) == set(graph.nodes)
        assert {edge.id: edge.evidence for edge in loaded.edges} == {edge.id: edge.evidence for edge in graph.edges}
        assert len([edge for edge in loaded.edges if edge.relationship.value == "depends_on"]) == 2
    finally:
        reset_current_tenant(token)
    token = set_current_tenant("other-tenant")
    try:
        assert not store.load_graph(tenant_id="other-tenant", scan_id=graph.scan_id).nodes
    finally:
        reset_current_tenant(token)


def test_identity_upgrade_preserves_snapshot_ids_and_ambiguous_aliases(migrated_fresh_database):
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore
    from tests.test_canonical_identity_boundaries import graph_identity_storage_contract
    from tests.test_graph_node_aliases import latest_snapshot_alias_contract

    store = PostgresGraphStore()
    token = set_current_tenant("identity-contract")
    try:
        graph_identity_storage_contract(store)
        latest_snapshot_alias_contract(store, tenant="identity-contract")
    finally:
        reset_current_tenant(token)


def test_merged_runtime_receipts_survive_postgres_replay(migrated_fresh_database):
    from dataclasses import replace

    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore
    from agent_bom.graph.path_evidence import annotate_attack_path_evidence
    from tests.test_exposure_path_evidence_parity import _serialize_both
    from tests.test_graph_typed_hop_boundaries import graph_and_path

    graph, path = graph_and_path()
    edge = graph.edges[0]
    graph.add_edge(replace(edge, evidence={"event_id": "event:2", "blocked": True}))
    graph.attack_paths = [annotate_attack_path_evidence(path, graph)]
    token = set_current_tenant("tenant")
    try:
        PostgresGraphStore().save_graph(graph)
        restored = PostgresGraphStore().load_graph(tenant_id="tenant", scan_id="snapshot")
        assert restored is not None
        for payload in _serialize_both(restored.attack_paths[0], nodes=list(restored.nodes.values()), edges=restored.edges):
            receipt = payload["hopEvidence"][0]
            assert receipt["canonical_edge_id"] == edge.canonical_id
            assert receipt["runtime_outcome"] == "blocked"
            assert {r["event_id"] for r in receipt["runtime_references"]} == {"event:1", "event:2"}
            assert payload["reachability"] == "unknown"
    finally:
        reset_current_tenant(token)
    token = set_current_tenant("other")
    try:
        other = PostgresGraphStore().load_graph(tenant_id="other", scan_id="snapshot")
        assert other is None or (not other.nodes and not other.edges and not other.attack_paths)
    finally:
        reset_current_tenant(token)


def test_unverified_scanner_match_survives_postgres_api_replay(migrated_fresh_database, tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    from agent_bom.api import stores
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore
    from agent_bom.api.postgres_job_store import PostgresJobStore
    from agent_bom.api.server import app
    from agent_bom.graph.builder import build_unified_graph_from_report
    from agent_bom.output import to_json
    from tests.test_scanner_range_surfaces import _candidate_report

    payload = to_json(_candidate_report(tmp_path))
    jobs, graphs = PostgresJobStore(), PostgresGraphStore()
    token = set_current_tenant("default")
    try:
        jobs.put(
            ScanJob(
                job_id="candidate-scan",
                tenant_id="default",
                status=JobStatus.DONE,
                created_at="2026-10-16T00:00:00Z",
                request=ScanRequest(),
                result=payload,
            )
        )
        graphs.save_graph(build_unified_graph_from_report(payload, scan_id="candidate-scan", tenant_id="default"))
        # Fresh store instances read database receipts, not writer-side objects.
        monkeypatch.setattr(stores, "_store", PostgresJobStore())
        monkeypatch.setattr(stores, "_graph_store", PostgresGraphStore())
        # A previous migration test may have built middleware against a pool
        # that its fixture closed. Bind this request stack to this fresh database.
        monkeypatch.setattr(app, "middleware_stack", None)
        client = TestClient(app)
        response = client.get("/v1/findings", params={"q": "CVE-2026-1234", "window_days": 0})
        assert response.status_code == 200
        rows = response.json()["findings"]
        assert len(rows) == 1
        assert rows[0]["match_confidence_tier"] == "unverified_range"
        assert rows[0]["reachability"] == "unknown"
        assert rows[0]["effective_reach_score"] is None
        graph = client.get("/v1/graph", params={"scan_id": "candidate-scan"}).json()
        assert graph["nodes"] and graph["edges"]
        other = PostgresGraphStore().load_graph(scan_id="candidate-scan", tenant_id="other")
        assert not other.nodes
    finally:
        reset_current_tenant(token)


def test_direct_scanner_scope_survives_postgres_replay(migrated_fresh_database):
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore
    from tests.test_multi_hop_blast_radius import direct_scope_storage_contract

    token = set_current_tenant("scope-contract")
    try:
        direct_scope_storage_contract(PostgresGraphStore())
    finally:
        reset_current_tenant(token)
