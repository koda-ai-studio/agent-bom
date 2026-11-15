"""Snapshot nodes, search rows and edges are written by COPY into session staging plus one set-based upsert per table.

The row-at-a-time path (one ``INSERT ... ON CONFLICT`` per row) took about
half of a 5,000-agent PostgreSQL push. The bulk path must write exactly the
same rows: duplicates inside one write resolve last-wins, edges carry
``first_seen``/``valid_from`` forward from the superseded scan, a retried scan
replaces itself, row-level security still applies, and a failure part way
through leaves nothing. ``AGENT_BOM_PG_GRAPH_BULK_WRITE=0`` keeps the old path.

Live tier: needs ``AGENT_BOM_POSTGRES_ADMIN_URL`` and ``AGENT_BOM_POSTGRES_URL``.
"""

from __future__ import annotations

import json
import os
from typing import Any

import pytest

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedNode
from tests.test_postgres_migrated_graph_parity import _with_database, migrated_fresh_database  # noqa: F401
from tests.test_postgres_migrated_graph_parity import pytestmark as pytestmark

_TABLES = {
    "graph_nodes": ("id",),
    "graph_node_search": ("node_id",),
    "graph_edges": ("source_id", "target_id", "relationship"),
    "graph_snapshots": (),
}


def _node(node_id: str, **overrides: Any) -> UnifiedNode:
    fields: dict[str, Any] = {
        "id": node_id,
        "entity_type": EntityType.PACKAGE,
        "label": f'label {node_id} "quoted" tab\tback\\slash ünïcode',
        "severity": "high",
        "risk_score": 0.1 + 0.2,
        "compliance_tags": ["SOC2-CC6.1"],
        "data_sources": ["sbom"],
        "attributes": {"version": "1.0", "nested": {"a": [1, 2.5, None, "x"]}},
        # Pinned: the defaults are the wall clock, which would differ between the two writes.
        "first_seen": "2026-10-01T00:00:00Z",
        "last_seen": "2026-10-01T00:00:00Z",
    }
    fields.update(overrides)
    return UnifiedNode(**fields)


def _edge(source: str, target: str, **overrides: Any) -> UnifiedEdge:
    fields: dict[str, Any] = {
        "source": source,
        "target": target,
        "relationship": RelationshipType.DEPENDS_ON,
        "weight": 1 / 3,
        "confidence": 0.7,
        "evidence": {"why": "lockfile", "line": 12},
        "first_seen": "2026-10-01T00:00:00Z",
        "last_seen": "2026-10-01T00:00:00Z",
    }
    fields.update(overrides)
    return UnifiedEdge(**fields)


def _first_scan() -> tuple[list[UnifiedNode], list[UnifiedEdge]]:
    nodes = [_node(f"package:n{i}") for i in range(40)]
    # Duplicates inside one write: the later row wins.
    nodes.append(_node("package:n3", label="n3 second", risk_score=9.5, attributes={"version": "2.0"}))
    nodes.append(_node("package:n3", label="n3 third", severity=None, risk_score=0.0))
    edges = [_edge(f"package:n{i}", f"package:n{i + 1}", first_seen="2026-10-01T00:00:00Z") for i in range(39)]
    edges.append(_edge("package:n1", "package:n2", weight=2.5, evidence={"why": "second"}, first_seen="2026-10-02T00:00:00Z"))
    edges.append(_edge("package:n5", "package:n6", relationship=RelationshipType.CONTAINS, valid_to=None))
    return nodes, edges


def _second_scan() -> tuple[list[UnifiedNode], list[UnifiedEdge]]:
    nodes = [_node(f"package:n{i}", label=f"v2 {i}") for i in range(30)]
    # Edges kept from the first scan carry its first_seen forward; new ones start now.
    edges = [_edge(f"package:n{i}", f"package:n{i + 1}", first_seen="2026-11-01T00:00:00Z") for i in range(25)]
    edges.append(_edge("package:n0", "package:n29", first_seen="2026-11-01T00:00:00Z"))
    edges.append(_edge("package:n0", "package:n29", weight=0.0, confidence=1.0, first_seen="2026-11-02T00:00:00Z"))
    return nodes, edges


def _save(tenant: str, scan: str, created_at: str, graph: tuple[list[UnifiedNode], list[UnifiedEdge]]) -> dict[str, int]:
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore

    token = set_current_tenant(tenant)
    try:
        return PostgresGraphStore().save_graph_streaming(
            scan_id=scan, tenant_id=tenant, nodes=iter(graph[0]), edges=iter(graph[1]), created_at=created_at
        )
    finally:
        reset_current_tenant(token)


def _push_history(tenant: str) -> list[dict[str, int]]:
    return [
        _save(tenant, "scan-1", "2026-10-01T00:00:00Z", _first_scan()),
        _save(tenant, "scan-2", "2026-11-01T00:00:00Z", _second_scan()),
        # A retried scan replaces itself and still reads scan-1 as its predecessor.
        _save(tenant, "scan-2", "2026-11-01T00:00:00Z", _second_scan()),
    ]


def _dump(database: str, tenant: str) -> dict[str, list[str]]:
    import psycopg

    dumped: dict[str, list[str]] = {}
    with psycopg.connect(_with_database(os.environ["AGENT_BOM_POSTGRES_ADMIN_URL"], database), autocommit=True) as conn:
        for table in _TABLES:
            cursor = conn.execute(f"SELECT * FROM {table} WHERE tenant_id = %s", (tenant,))  # nosec B608 - fixed test tables
            names = [column.name for column in cursor.description]
            rows = []
            for row in cursor.fetchall():
                record = dict(zip(names, row))
                record.pop("tenant_id")
                for volatile in ("snapshot_generation", "read_revision", "updated_at"):
                    record.pop(volatile, None)
                rows.append(json.dumps(record, sort_keys=True, default=repr))
            dumped[table] = sorted(rows)
    return dumped


def _with_path(monkeypatch, bulk: bool) -> None:
    monkeypatch.setenv("AGENT_BOM_PG_GRAPH_BULK_WRITE", "1" if bulk else "0")


def _spy_bulk(monkeypatch) -> list[str]:
    from agent_bom.api import postgres_graph_bulk

    used: list[str] = []
    original = postgres_graph_bulk.copy_stage

    def spy(conn, stage, *args, **kwargs):
        used.append(stage)
        return original(conn, stage, *args, **kwargs)

    monkeypatch.setattr(postgres_graph_bulk, "copy_stage", spy)
    return used


@pytest.mark.parametrize("batch", [None, "7"])
def test_bulk_and_row_paths_write_identical_rows(migrated_fresh_database, monkeypatch, batch) -> None:  # noqa: F811
    if batch:
        monkeypatch.setenv("AGENT_BOM_GRAPH_WRITE_BATCH_SIZE", batch)  # duplicates then span batches
    used = _spy_bulk(monkeypatch)
    _with_path(monkeypatch, bulk=False)
    row_counts = _push_history("tenant-row")
    row_stages = len(used)
    _with_path(monkeypatch, bulk=True)
    bulk_counts = _push_history("tenant-bulk")
    bulk_stages = len(used) - row_stages
    assert row_stages == 0, "the row path must not stage"
    assert bulk_stages > 0, "the bulk path never staged"
    assert row_counts == bulk_counts
    row, bulk = _dump(migrated_fresh_database, "tenant-row"), _dump(migrated_fresh_database, "tenant-bulk")
    for table in _TABLES:
        assert row[table], table
        assert bulk[table] == row[table], table
    # The duplicate rule held: the last n3 row won, and the carried-forward first_seen came from scan-1.
    n3 = [json.loads(r) for r in bulk["graph_nodes"] if json.loads(r)["id"] == "package:n3"]
    assert sorted(r["label"] for r in n3) == ["n3 third", "v2 3"], "scan-1 keeps the last duplicate; scan-2 its own row"


def test_bulk_write_leaves_another_tenants_rows_untouched(migrated_fresh_database, monkeypatch) -> None:  # noqa: F811
    _with_path(monkeypatch, bulk=True)
    _save("tenant-b", "scan-1", "2026-10-01T00:00:00Z", _first_scan())
    before = _dump(migrated_fresh_database, "tenant-b")
    # Same scan id and node ids for another tenant, written twice.
    _save("tenant-a", "scan-1", "2026-10-01T00:00:00Z", _second_scan())
    _save("tenant-a", "scan-1", "2026-10-01T00:00:00Z", _first_scan())
    assert _dump(migrated_fresh_database, "tenant-b") == before


def test_bulk_write_runs_as_the_rls_app_role_and_cannot_write_another_tenant(migrated_fresh_database, monkeypatch) -> None:  # noqa: F811
    """The staged rows go through the same RLS check as the row path: a tenant mismatch is refused, nothing lands."""
    from agent_bom.api import postgres_common

    _with_path(monkeypatch, bulk=True)
    original = postgres_common._apply_tenant_session

    def wrong_tenant(conn, **kwargs):
        original(conn, **kwargs)
        conn.execute("SELECT set_config('app.tenant_id', 'tenant-other', true)")

    monkeypatch.setattr(postgres_common, "_apply_tenant_session", wrong_tenant)
    with pytest.raises(Exception):
        _save("tenant-a", "scan-1", "2026-10-01T00:00:00Z", _first_scan())
    monkeypatch.setattr(postgres_common, "_apply_tenant_session", original)
    assert all(not rows for rows in _dump(migrated_fresh_database, "tenant-a").values())


@pytest.mark.parametrize("where", ["nodes", "edges", "invalid-json"])
def test_a_failure_part_way_leaves_nothing_and_keeps_the_previous_write(migrated_fresh_database, monkeypatch, where) -> None:  # noqa: F811
    _with_path(monkeypatch, bulk=True)
    monkeypatch.setenv("AGENT_BOM_GRAPH_WRITE_BATCH_SIZE", "7")  # several COPY batches before the failure
    _save("tenant-a", "scan-1", "2026-10-01T00:00:00Z", _first_scan())
    kept = _dump(migrated_fresh_database, "tenant-a")
    nodes, edges = _second_scan()

    def failing(items: list[Any], after: int):
        for index, item in enumerate(items):
            if index == after:
                raise RuntimeError("producer failed part way")
            yield item

    if where == "nodes":
        graph: tuple[Any, Any] = (failing(nodes, 20), iter(edges))
    elif where == "edges":
        graph = (iter(nodes), failing(edges, 20))
    else:
        from agent_bom.api import postgres_graph_write

        real = postgres_graph_write._node_row

        def bad_row(node, **kwargs):
            row = list(real(node, **kwargs))
            if node.id == "package:n15":
                row[12] = '{"not json'
            return tuple(row)

        monkeypatch.setattr(postgres_graph_write, "_node_row", bad_row)
        graph = (iter(nodes), iter(edges))
    with pytest.raises(Exception):
        _save("tenant-a", "scan-1", "2026-10-01T00:00:00Z", graph)
    assert _dump(migrated_fresh_database, "tenant-a") == kept


def test_the_row_path_stays_available_for_one_release(monkeypatch) -> None:
    from agent_bom.api import postgres_graph_bulk

    monkeypatch.delenv("AGENT_BOM_PG_GRAPH_BULK_WRITE", raising=False)
    assert postgres_graph_bulk.bulk_enabled() is True
    monkeypatch.setenv("AGENT_BOM_PG_GRAPH_BULK_WRITE", "0")
    assert postgres_graph_bulk.bulk_enabled() is False


def test_bulk_and_row_paths_write_identical_rows_for_a_generated_estate(migrated_fresh_database, monkeypatch) -> None:  # noqa: F811
    from agent_bom.graph.builder import build_unified_graph_from_report
    from scripts.generate_graph_benchmark_estate import generate_estate

    def graph(seed: int):
        report, _summary = generate_estate(agents=60, seed=seed, vulnerable_package_rate=0.08)
        built = build_unified_graph_from_report(report, tenant_id="estate", scan_id=f"estate-{seed}")
        return list(built.nodes.values()), list(built.edges)

    # Built once: the builder stamps wall-clock first_seen/last_seen, which is not the write path's doing.
    estates = {seed: graph(seed) for seed in (2145, 2146)}
    for tenant, bulk in (("estate-row", False), ("estate-bulk", True)):
        _with_path(monkeypatch, bulk)
        _save(tenant, "estate-2145", "2026-10-01T00:00:00Z", estates[2145])
        _save(tenant, "estate-2146", "2026-11-01T00:00:00Z", estates[2146])
    row, bulk_rows = _dump(migrated_fresh_database, "estate-row"), _dump(migrated_fresh_database, "estate-bulk")
    for table in _TABLES:
        assert len(row[table]) > 50 or table == "graph_snapshots", table
        assert bulk_rows[table] == row[table], table


def test_switching_paths_between_saves_on_a_pooled_connection(migrated_fresh_database, monkeypatch) -> None:  # noqa: F811
    """A connection that staged for one save carries no staging state into the next save."""
    from agent_bom.api import postgres_common

    monkeypatch.setenv("AGENT_BOM_POSTGRES_POOL_MAX_SIZE", "1")
    postgres_common.reset_pool()
    for bulk in (True, False, True, False):
        _with_path(monkeypatch, bulk)
        _save("tenant-switch", "scan-1", "2026-10-01T00:00:00Z", _first_scan())
    _with_path(monkeypatch, bulk=False)
    _save("tenant-switch-row", "scan-1", "2026-10-01T00:00:00Z", _first_scan())
    assert _dump(migrated_fresh_database, "tenant-switch") == _dump(migrated_fresh_database, "tenant-switch-row")
