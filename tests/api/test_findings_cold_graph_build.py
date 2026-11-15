"""Findings never wait on a tenant's first current-graph build: rows at once, reach labelled refreshing.

Graph reads keep their cold-start read-your-writes wait. Findings rows come
from the finding store and are listed at once; only their graph reachability
waits for the build, and says so (``graph_refreshing``).
"""

from __future__ import annotations

import time

import pytest
from starlette.testclient import TestClient

from agent_bom.api import current_graph_builds, stores
from agent_bom.api.current_graph import current_graph_store, graph_scan_id
from agent_bom.api.current_graph_builds import await_current_build
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.graph import AttackPath, EntityType, UnifiedGraph, UnifiedNode
from tests.api.test_current_graph_unpinned_reads import _hold_materialize, private_build_queue  # noqa: F401
from tests.api.test_scan_job_sla_history import job, scan_store  # noqa: F401
from tests.auth_helpers import proxy_headers

TENANT = "history-tenant"
CVE = "CVE-2026-4242"


@pytest.fixture()
def graph_store(tmp_path, monkeypatch):
    store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    monkeypatch.setattr(stores, "_graph_store", store)
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS", "5000")
    return store


def _push(scan_store, graph_store, month: int, tenant: str = TENANT, *, reachable: bool = True):  # noqa: F811
    row = job(month, tenant=tenant)
    graph = UnifiedGraph(scan_id=graph_scan_id(row), tenant_id=tenant, created_at=row.completed_at)
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a"))
    graph.add_node(UnifiedNode(id="pkg:pypi/demo-lib@1.0.0", entity_type=EntityType.PACKAGE, label="demo-lib"))
    if reachable:
        graph.attack_paths.append(
            AttackPath(
                source="agent:a",
                target="pkg:pypi/demo-lib@1.0.0",
                hops=["agent:a", "pkg:pypi/demo-lib@1.0.0"],
                edges=["uses"],
                composite_risk=9.0,
                summary="agent reaches a vulnerable package",
                vuln_ids=[CVE],
            )
        )
    graph_store.save_graph(graph)
    scan_store.put(row)
    return row


def _findings(client: TestClient, tenant: str = TENANT) -> tuple[float, dict]:
    began = time.monotonic()
    response = client.get("/v1/findings", params={"window_days": 0}, headers=proxy_headers(role="analyst", tenant=tenant))
    assert response.status_code == 200, response.text
    return time.monotonic() - began, response.json()


def _reach(body: dict) -> list[tuple]:
    return [(row.get("graph_reachable"), row.get("graph_reachability_not_assessed_reason")) for row in body["findings"]]


def _wrapper():
    return current_graph_store(stores._graph_store, stores._store)


def test_a_cold_build_answers_at_once_with_every_finding_and_reach_refreshing(scan_store, graph_store):  # noqa: F811
    _push(scan_store, graph_store, 8)
    entered, release = _hold_materialize(_wrapper())
    try:
        with TestClient(app) as client:
            elapsed, body = _findings(client)
        assert entered.wait(5), "the findings read never started the tenant's first build"
    finally:
        release.set()
    assert elapsed < 1.5, f"the findings read waited {elapsed:.2f}s on the first build"
    assert len(body["findings"]) == 1, "a pushed finding must be listed at once"
    assert body["findings"][0].get("cve_id") == CVE or CVE in str(body["findings"][0])
    assert _reach(body) == [(None, "graph_refreshing")]
    assert body["graph_freshness"] == {"refresh_status": "building"}
    assert any("being prepared" in warning for warning in body["warnings"])


def test_after_promotion_reach_is_filled_in(scan_store, graph_store):  # noqa: F811
    _push(scan_store, graph_store, 8)
    assert await_current_build(_wrapper(), TENANT, seconds=10)
    with TestClient(app) as client:
        _elapsed, body = _findings(client)
    # Assessed against the promoted generation: no refreshing label, no freshness envelope.
    # (This two-node fixture has no topology for a path, so the assessed answer is "no match".)
    assert _reach(body) == [(None, None)]
    assert "graph_freshness" not in body
    assert not any("being prepared" in warning for warning in body["warnings"])


def test_a_warm_rebuild_serves_the_previous_generation_labelled(scan_store, graph_store):  # noqa: F811
    _push(scan_store, graph_store, 8)
    assert await_current_build(_wrapper(), TENANT, seconds=10)
    entered, release = _hold_materialize(_wrapper())
    _push(scan_store, graph_store, 9)
    try:
        with TestClient(app) as client:
            elapsed, body = _findings(client)
        assert entered.wait(5)
    finally:
        release.set()
    assert elapsed < 1.5
    assert _reach(body) == [(None, "graph_refreshing")]
    assert body["graph_freshness"]["refresh_status"] == "building"
    assert body["graph_freshness"]["freshness"] == "previous_generation"
    assert body["graph_freshness"]["as_of"]


def test_graph_reads_keep_the_cold_start_wait(scan_store, graph_store, monkeypatch):  # noqa: F811
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS", "300")
    _push(scan_store, graph_store, 8)
    entered, release = _hold_materialize(_wrapper())
    try:
        with TestClient(app) as client:
            began = time.monotonic()
            response = client.get("/v1/graph", headers=proxy_headers(role="analyst", tenant=TENANT))
            elapsed = time.monotonic() - began
        assert entered.wait(5)
    finally:
        release.set()
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "current_estate_building"
    assert elapsed >= 0.25, "a cold graph read still waits its read-your-writes budget"


def test_tenant_scoping_holds_while_one_tenant_builds(scan_store, graph_store):  # noqa: F811
    _push(scan_store, graph_store, 8)
    other = _push(scan_store, graph_store, 8, tenant="other-tenant", reachable=False)
    assert await_current_build(_wrapper(), "other-tenant", seconds=10)
    entered, release = _hold_materialize(_wrapper())
    try:
        with TestClient(app) as client:
            _elapsed, mine = _findings(client)
            _elapsed, theirs = _findings(client, "other-tenant")
        assert entered.wait(5)
    finally:
        release.set()
    assert _reach(mine) == [(None, "graph_refreshing")]
    # The other tenant's promoted graph serves it as usual; no label, nothing from the building tenant.
    assert "graph_freshness" not in theirs
    assert len(theirs["findings"]) == 1
    assert theirs["findings"][0].get("graph_reachability_not_assessed_reason") is None
    assert other.job_id not in str(mine)
    assert current_graph_builds  # the private queue fixture keeps builds isolated per test
