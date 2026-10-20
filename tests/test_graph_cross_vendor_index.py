"""Endpoint vendors are stored on each materialized path row, so the cross-vendor queue is an indexed read."""

from __future__ import annotations

import sqlite3
from uuid import uuid4

from agent_bom.graph.attack_path_queue_rank import rank_attack_paths
from agent_bom.graph.path_derivation import _derived_attack_paths
from agent_bom.graph.path_vendors import path_vendor_pair
from agent_bom.graph.snapshot_paths import materialize_snapshot_paths
from tests.test_graph_cross_vendor_queue import _graph
from tests.test_graph_tenant_scope_and_bounds import api  # noqa: F401
from tests.test_postgres_graph_snapshot_paths import store, tenant_scope  # noqa: F401


def test_materialized_rows_record_endpoint_vendors():
    rows = {(row.path.source, row.path.target): row for row in materialize_snapshot_paths(_graph("t"))}
    stored = rows[("snowflake:table:T", "aws:bucket:B")]
    assert (stored.source_vendor, stored.target_vendor) == ("snowflake", "aws")
    agent = rows[("agent:a", "server:s")]
    assert (agent.source_vendor, agent.target_vendor) == ("", "")


def test_indexed_cross_vendor_page_matches_the_ranked_classification(store):  # noqa: F811
    tenant, scan = f"cv-{uuid4().hex[:8]}", f"cv-scan-{uuid4().hex[:8]}"
    graph = _graph(tenant)
    graph.scan_id = scan
    with tenant_scope(tenant):
        store.save_graph(graph)
        loaded = store.load_graph(tenant_id=tenant, scan_id=scan)
        whole = store.snapshot_cross_vendor_page(tenant_id=tenant, scan_id=scan, offset=0, limit=10)
        narrowed = store.snapshot_cross_vendor_page(tenant_id=tenant, scan_id=scan, offset=0, limit=10, source_vendor="snowflake")
        other_tenant = store.snapshot_cross_vendor_page(tenant_id=f"other-{tenant}", scan_id=scan, offset=0, limit=10)
        store.delete_snapshot(tenant_id=tenant, scan_id=scan)
    ranked = rank_attack_paths(_derived_attack_paths(loaded), loaded.nodes)
    expected = [path for path in ranked if path_vendor_pair(path, loaded.nodes)]
    assert whole is not None and whole.total == len(expected) == 2
    assert [path.to_dict() for path in whole.paths] == [path.to_dict() for path in expected]
    assert whole.snapshot_total == len(ranked)
    assert whole.pairs == [("github", "aws", 1), ("snowflake", "aws", 1)]
    assert narrowed is not None and [path.source for path in narrowed.paths] == ["snowflake:table:T"]
    assert narrowed.total == 1 and narrowed.pairs == whole.pairs
    assert other_tenant is None or (other_tenant.total == 0 and other_tenant.pairs == [])


def test_route_reads_the_index_instead_of_the_whole_queue(api, monkeypatch):  # noqa: F811
    from agent_bom.api.routes.graph_routes import vendor_paths

    client, graph_store, headers = api
    graph_store.save_graph(_graph("tenant-a"))

    async def _whole_queue(*_args, **_kwargs):
        raise AssertionError("the stored index should answer the cross-vendor queue")

    monkeypatch.setattr(vendor_paths, "whole_queue", _whole_queue)
    response = client.get("/v1/graph/attack-paths/cross-vendor", params={"scan_id": "vendor-scan", "limit": 1}, headers=headers["tenant-a"])
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["pagination"]["total"] == 2 and body["pagination"]["has_more"] is True
    assert body["vendor_facets"]["cross_vendor_paths"] == 2
    assert body["vendor_facets"]["snapshot_paths"] == 4
    assert body["vendor_facets"]["covers_all_paths"] is True


def test_existing_sqlite_store_gains_the_vendor_columns(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    path = tmp_path / "graph.db"
    SQLiteGraphStore(path).save_graph(_graph("t"))
    conn = sqlite3.connect(path)
    conn.execute("DROP INDEX idx_gap_vendor")
    conn.execute("ALTER TABLE graph_attack_paths DROP COLUMN source_vendor")
    conn.execute("ALTER TABLE graph_attack_paths DROP COLUMN target_vendor")
    conn.commit()
    conn.close()
    reopened = SQLiteGraphStore(path)
    reopened.save_graph(_graph("t"))
    columns = {row[1] for row in sqlite3.connect(path).execute("PRAGMA table_info(graph_attack_paths)")}
    assert {"source_vendor", "target_vendor"} <= columns
    page = reopened.snapshot_cross_vendor_page(tenant_id="t", scan_id="vendor-scan", offset=0, limit=5)
    assert page is not None and page.total == 2
