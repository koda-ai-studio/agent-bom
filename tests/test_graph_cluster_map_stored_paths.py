"""The grouped map marks attack paths from the snapshot's stored path index, through the real scan persist path.

A scan graph carries no legacy ``attack_paths`` rows: its paths are materialized
into ``graph_attack_paths`` at persist time. The map must mark exactly the
nodes and hops that ``GET /v1/graph/attack-paths`` serves for the same snapshot,
on SQLite and (when ``AGENT_BOM_POSTGRES_URL`` is set) on Postgres.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent_bom.api import auth, graph_cluster_index_cache, stores
from agent_bom.api.graph_persistence import persist_graph_snapshot
from agent_bom.api.middleware import APIKeyMiddleware, TrustHeadersMiddleware
from agent_bom.api.routes import graph as routes
from tests.graph.test_snapshot_paths import shared_server_estate

pytestmark = pytest.mark.graph_contract("warn")


@pytest.fixture(params=["sqlite", "postgres"])
def backend(request, tmp_path):
    if request.param == "sqlite":
        from agent_bom.api.graph_store import SQLiteGraphStore

        yield "sqlite", SQLiteGraphStore(tmp_path / "graph.db")
        return
    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("AGENT_BOM_POSTGRES_URL is required for live Postgres grouped-map reads")
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_graph import PostgresGraphStore

    pool = _new_application_pool(min_size=1, max_size=2)
    try:
        yield "postgres", PostgresGraphStore(pool=pool)
    finally:
        pool.close()


@contextmanager
def tenant_scope(tenant: str):
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    token = set_current_tenant(tenant)
    try:
        yield
    finally:
        reset_current_tenant(token)


def _count(store, kind: str, sql: str, params: tuple[str, str]) -> int:
    if kind == "sqlite":
        conn = store._open_ro_conn()
        try:
            return int(conn.execute(sql, params).fetchone()[0])
        finally:
            conn.close()
    from agent_bom.api.postgres_common import _tenant_connection

    with _tenant_connection(store._pool) as conn:
        return int(conn.execute(sql.replace("?", "%s"), params).fetchone()[0])


@pytest.fixture
def scanned(backend, monkeypatch):
    from agent_bom.backpressure import reset_backpressure_for_tests

    kind, store = backend
    tenant, scan = f"t-{uuid4().hex[:8]}", f"s-{uuid4().hex[:8]}"
    monkeypatch.setenv("AGENT_BOM_GRAPH_ROLLUP_PREWARM", "0")
    monkeypatch.setenv("AGENT_BOM_FINDING_REACHABILITY_PREWARM", "0")
    monkeypatch.delenv("AGENT_BOM_MCP_TENANT_ID", raising=False)
    monkeypatch.delenv("AGENT_BOM_TENANT_ID", raising=False)
    reset_backpressure_for_tests()
    graph_cluster_index_cache.clear()
    job = SimpleNamespace(job_id=scan, tenant_id=tenant, progress=[], result={})
    persist_graph_snapshot(job, shared_server_estate(agents=12, group_size=4, scan_id=scan), store_factory=lambda: store)
    monkeypatch.setattr(stores, "_graph_store", store)
    keys = auth.KeyStore()
    monkeypatch.setattr(auth, "_key_store", keys)
    token, key = auth.create_api_key(tenant, auth.Role.VIEWER, tenant_id=tenant)
    keys.add(key)
    app = FastAPI()
    app.include_router(routes.router, prefix="/v1")
    app.add_middleware(APIKeyMiddleware, api_key="", allow_unauthenticated=False)
    app.add_middleware(TrustHeadersMiddleware)
    try:
        with TestClient(app) as client:
            yield kind, store, client, {"Authorization": f"Bearer {token}"}, tenant, scan
    finally:
        graph_cluster_index_cache.clear()
        reset_backpressure_for_tests()


def _all_paths(client, headers, scan: str) -> tuple[list[dict], int]:
    body = client.get("/v1/graph/attack-paths", params={"scan_id": scan, "limit": 1000}, headers=headers).json()
    assert body["pagination"]["has_more"] is False
    return body["attack_paths"], int(body["pagination"]["total"])


def test_scan_persisted_paths_mark_the_grouped_map_like_the_attack_path_queue(scanned) -> None:
    kind, store, client, headers, tenant, scan = scanned
    params = (tenant, scan)
    with tenant_scope(tenant):
        legacy = _count(store, kind, "SELECT COUNT(*) FROM attack_paths WHERE tenant_id = ? AND scan_id = ?", params)
        stored = _count(store, kind, "SELECT COUNT(*) FROM graph_attack_paths WHERE tenant_id = ? AND scan_id = ?", params)
    # The real scan shape: no legacy rows, every path in the snapshot index.
    assert legacy == 0
    assert stored > 0

    paths, total = _all_paths(client, headers, scan)
    assert total == stored == len(paths)
    on_path_nodes = {hop for path in paths for hop in path["hops"]}

    body = client.get("/v1/graph/cluster-map", params={"scan_id": scan}, headers=headers).json()
    clusters = [node for node in body["nodes"] if node.get("kind") == "cluster"]
    members = [node for node in body["nodes"] if node.get("kind") == "member"]
    marked = sum(int(node["on_attack_path_count"]) for node in clusters) + sum(1 for node in members if node["on_attack_path"])
    assert marked == len(on_path_nodes) > 0
    assert any(edge["on_attack_path"] for edge in body["edges"])

    for path in paths:
        focus = client.get("/v1/graph/cluster-map", params={"scan_id": scan, "focus": path["hops"][0]}, headers=headers).json()
        entry = next(node for node in focus["nodes"] if node.get("id") == path["hops"][0])
        assert entry["on_attack_path"] is True
        break


def test_per_source_path_reads_serve_the_stored_paths_the_queue_serves(scanned) -> None:
    _kind, _store, client, headers, _tenant, scan = scanned
    paths, _total = _all_paths(client, headers, scan)
    source = paths[0]["source"]
    expected = sorted(tuple(path["hops"]) for path in paths if path["source"] == source)
    assert expected

    node = client.get("/v1/graph/paths", params={"source_id": source, "scan_id": scan}, headers=headers).json()
    assert sorted(tuple(path["hops"]) for path in node["attack_paths"]) == expected

    query = client.post("/v1/graph/query", json={"scan_id": scan, "roots": [source], "include_attack_paths": True}, headers=headers).json()
    assert sorted(tuple(path["hops"]) for path in query["attack_paths"]) == expected
