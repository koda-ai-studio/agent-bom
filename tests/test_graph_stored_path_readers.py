"""Every per-snapshot attack-path reader serves the stored path index on scan snapshots.

Scans persist their paths only in ``graph_attack_paths``. Each reader here used
to read the legacy ``attack_paths`` table, which scans leave empty, so finding
reachability, the graph diff, scenario comparison, impact depth and attack-path
delta alerts all saw zero paths. Each test goes through the real scan persist
path and compares with ``GET /v1/graph/attack-paths`` for the same snapshot, on
SQLite and (with ``AGENT_BOM_POSTGRES_URL``) Postgres.
"""

from __future__ import annotations

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
from tests.test_graph_cluster_map_stored_paths import _count, backend, tenant_scope  # noqa: F401 - shared fixtures

pytestmark = pytest.mark.graph_contract("warn")


@pytest.fixture
def env(backend, monkeypatch):  # noqa: F811 - the imported fixture
    from agent_bom.api.finding_reachability import clear_reachability_index_cache
    from agent_bom.backpressure import reset_backpressure_for_tests

    kind, store = backend
    for name in ("AGENT_BOM_GRAPH_ROLLUP_PREWARM", "AGENT_BOM_FINDING_REACHABILITY_PREWARM"):
        monkeypatch.setenv(name, "0")
    monkeypatch.delenv("AGENT_BOM_MCP_TENANT_ID", raising=False)
    monkeypatch.delenv("AGENT_BOM_TENANT_ID", raising=False)
    reset_backpressure_for_tests()
    graph_cluster_index_cache.clear()
    clear_reachability_index_cache()
    alerts: list[dict] = []
    monkeypatch.setattr("agent_bom.graph.webhooks.dispatch_delta_alerts", lambda found, **_kw: alerts.extend(found) or None)
    monkeypatch.setattr(stores, "_graph_store", store)
    yield kind, store, alerts
    graph_cluster_index_cache.clear()
    clear_reachability_index_cache()
    reset_backpressure_for_tests()


def _persist(store, tenant: str, scan: str, *, agents: int) -> None:
    job = SimpleNamespace(job_id=scan, tenant_id=tenant, progress=[], result={})
    persist_graph_snapshot(job, shared_server_estate(agents=agents, group_size=4, scan_id=scan), store_factory=lambda: store)


def _client(tenant: str, monkeypatch) -> tuple[TestClient, dict[str, str]]:
    keys = auth.KeyStore()
    monkeypatch.setattr(auth, "_key_store", keys)
    token, key = auth.create_api_key(tenant, auth.Role.VIEWER, tenant_id=tenant)
    keys.add(key)
    app = FastAPI()
    app.include_router(routes.router, prefix="/v1")
    app.add_middleware(APIKeyMiddleware, api_key="", allow_unauthenticated=False)
    app.add_middleware(TrustHeadersMiddleware)
    return TestClient(app), {"Authorization": f"Bearer {token}"}


def _queue(client: TestClient, headers: dict[str, str], scan: str) -> list[dict]:
    body = client.get("/v1/graph/attack-paths", params={"scan_id": scan, "limit": 1000}, headers=headers).json()
    assert body["pagination"]["has_more"] is False and body["attack_paths"]
    return body["attack_paths"]


def _legacy_rows(store, kind: str, tenant: str, scan: str) -> int:
    with tenant_scope(tenant):
        return _count(store, kind, "SELECT COUNT(*) FROM attack_paths WHERE tenant_id = ? AND scan_id = ?", (tenant, scan))


def test_store_path_reads_serve_the_queue_paths(env, monkeypatch) -> None:
    kind, store, _alerts = env
    tenant, scan = f"t-{uuid4().hex[:8]}", f"s-{uuid4().hex[:8]}"
    _persist(store, tenant, scan, agents=8)
    assert _legacy_rows(store, kind, tenant, scan) == 0
    client, headers = _client(tenant, monkeypatch)
    with client:
        queue = _queue(client, headers, scan)
    expected = sorted(tuple(path["hops"]) for path in queue)
    with tenant_scope(tenant):
        # Paging, the read finding reachability, the diff and scenario comparison use.
        effective, _created, page, total = store.attack_paths(tenant_id=tenant, scan_id=scan, offset=0, limit=1000)
        assert (effective, total) == (scan, len(queue))
        assert sorted(tuple(path.hops) for path in page) == expected
        second = store.attack_paths(tenant_id=tenant, scan_id=scan, offset=1, limit=1)[2]
        assert [path.hops for path in second] == [page[1].hops]
        # Per-source reads.
        source = queue[0]["source"]
        by_source = store.attack_paths_for_sources(tenant_id=tenant, scan_id=scan, source_ids={source})
        assert sorted(tuple(path.hops) for path in by_source) == sorted(tuple(p["hops"]) for p in queue if p["source"] == source)
        # Impact depth: the longest stored path ending at a finding.
        target = queue[0]["target"]
        longest = max(len(p["hops"]) - 1 for p in queue if p["target"] == target)
        assert store.longest_path_to(tenant_id=tenant, scan_id=scan, node_id=target) == longest > 0


def test_finding_reachability_marks_findings_on_stored_paths(env) -> None:
    from agent_bom.api.finding_reachability import project_persisted_graph_reachability

    _kind, store, _alerts = env
    tenant, scan = f"t-{uuid4().hex[:8]}", f"s-{uuid4().hex[:8]}"
    _persist(store, tenant, scan, agents=4)
    rows = [
        {"vulnerability_id": "CVE-2026-00000", "finding_node_id": "vuln:CVE-2026-00000"},
        {"vulnerability_id": "CVE-2099-99999", "finding_node_id": "vuln:CVE-2099-99999"},
    ]
    with tenant_scope(tenant):
        projected = project_persisted_graph_reachability(rows, graph_store=store, tenant_id=tenant, scan_id=scan).rows
    assert projected[0]["graph_reachable"] is True
    assert projected[0]["graph_min_hop_distance"] is not None
    assert projected[1]["graph_reachable"] is not True


def test_graph_diff_counts_new_attack_paths_between_scans(env, monkeypatch) -> None:
    _kind, store, _alerts = env
    tenant, old, new = f"t-{uuid4().hex[:8]}", f"s-old-{uuid4().hex[:6]}", f"s-new-{uuid4().hex[:6]}"
    _persist(store, tenant, old, agents=4)
    _persist(store, tenant, new, agents=8)
    client, headers = _client(tenant, monkeypatch)
    with client:
        old_paths = {tuple(path["hops"]) for path in _queue(client, headers, old)}
        new_paths = {tuple(path["hops"]) for path in _queue(client, headers, new)}
        body = client.get("/v1/graph/diff", params={"old": old, "new": new}, headers=headers).json()
    added = new_paths - old_paths
    assert added
    highlight = body["summary"]["highlights"]["new_attack_paths"]
    assert highlight["status"] == "complete", highlight
    assert highlight["count"] == len(added), highlight


def test_scenario_comparison_counts_the_stored_paths(env, monkeypatch) -> None:
    from agent_bom.api.graph_scenario_store import InMemoryGraphScenarioStore
    from agent_bom.api.server import app

    _kind, store, _alerts = env
    tenant, scan = "default", f"s-{uuid4().hex[:8]}"
    _persist(store, tenant, scan, agents=4)
    previous_graph, previous_scenarios = stores._graph_store, stores._graph_scenario_store
    stores.set_graph_store(store)
    stores.set_graph_scenario_store(InMemoryGraphScenarioStore())
    try:
        client = TestClient(app)
        queue_total = client.get("/v1/graph/attack-paths", params={"scan_id": scan, "limit": 1}).json()["pagination"]["total"]
        created = client.post(
            "/v1/graph/scenarios",
            json={
                "name": "Rotate the shared token",
                "base_scan_id": scan,
                "changes": [{"kind": "patch_node", "node_id": "agent:agent-0000-000", "patch": {"risk_score": 1.0}}],
                "assumptions": ["Token rotated"],
            },
        )
        assert created.status_code == 201, created.text
        scenario_id = created.json()["scenario"]["scenario_id"]
        comparison = client.get(f"/v1/graph/scenarios/{scenario_id}/comparison", params={"scan_id": scan})
        assert comparison.status_code == 200, comparison.text
        paths = comparison.json()["current"]["path_completeness"]
        assert paths["total"] == queue_total > 0
        assert paths["returned"] == min(queue_total, paths["returned"]) > 0
    finally:
        stores.set_graph_store(previous_graph)
        stores.set_graph_scenario_store(previous_scenarios)


def test_delta_alerts_fire_for_new_attack_paths_and_only_those(env, monkeypatch) -> None:
    _kind, store, alerts = env
    tenant = f"t-{uuid4().hex[:8]}"
    _persist(store, tenant, f"s-a-{uuid4().hex[:6]}", agents=4)
    alerts.clear()
    newer = f"s-b-{uuid4().hex[:6]}"
    _persist(store, tenant, newer, agents=8)
    client, headers = _client(tenant, monkeypatch)
    with client:
        endpoints = {(p["source"], p["target"]) for p in _queue(client, headers, newer)}
    new_routes = {(s, t) for s, t in endpoints if "agent-0001-" in s}
    fired = {(a["details"]["node_ids"][0], a["details"]["node_ids"][-1]) for a in alerts if a.get("type") == "new_attack_path"}
    # High-risk new routes alert; routes the previous scan already had never do.
    assert new_routes and fired and fired <= new_routes
    alerts.clear()
    _persist(store, tenant, f"s-c-{uuid4().hex[:6]}", agents=8)
    assert [a for a in alerts if a.get("type") == "new_attack_path"] == []
