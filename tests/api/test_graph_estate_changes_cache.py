"""Repeat ``/v1/graph/changes`` pages reuse their work instead of re-reading every job and diff."""

from __future__ import annotations

import pytest

from agent_bom.api import graph_diff_read, graph_estate_changes, stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.store import SQLiteJobStore
from tests.api.test_graph_estate_changes import TENANT, by_label, client, record, seed
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env


@pytest.fixture
def estate(tmp_path, monkeypatch):
    jobs = SQLiteJobStore(str(tmp_path / "jobs.db"))
    graph_store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    monkeypatch.setattr(stores, "_store", jobs)
    monkeypatch.setattr(stores, "_graph_store", graph_store)
    graph_estate_changes.reset_estate_changes_caches()
    enable_trusted_proxy_env()
    yield jobs, graph_store
    disable_trusted_proxy_env()
    graph_estate_changes.reset_estate_changes_caches()


class _Spy:
    def __init__(self, monkeypatch, owner, name):
        self.calls = 0
        original = getattr(owner, name)

        def counted(*args, **kwargs):
            self.calls += 1
            return original(*args, **kwargs)

        monkeypatch.setattr(owner, name, counted)


def test_rows_cache_key_reads_only_snapshot_identity(estate, monkeypatch):
    seed(estate)
    _jobs, graph_store = estate
    forbidden = ("diff_snapshots", "load_graph", "iter_nodes", "iter_edges", "nodes_by_ids", "attack_paths", "page_nodes")
    for name in forbidden:
        monkeypatch.setattr(graph_store, name, lambda *a, _name=name, **k: pytest.fail(f"cache key materialised rows via {_name}"))

    key = graph_diff_read._rows_cache_key(graph_store, TENANT, f"{TENANT}-repo-a-7", f"{TENANT}-repo-a-8")

    assert key is not None
    assert key == graph_diff_read._rows_cache_key(graph_store, TENANT, f"{TENANT}-repo-a-7", f"{TENANT}-repo-a-8")


def test_second_page_hits_the_caches(estate, monkeypatch):
    seed(estate)
    jobs, graph_store = estate
    with client() as http:
        first = http.get("/v1/graph/changes?limit=20")
        job_reads = _Spy(monkeypatch, type(jobs), "get")
        diffs = _Spy(monkeypatch, type(graph_store), "diff_snapshots")
        paths = _Spy(monkeypatch, type(graph_store), "attack_paths")
        second = http.get("/v1/graph/changes?limit=20")

    assert first.status_code == second.status_code == 200, second.text
    assert second.json() == first.json()
    assert (job_reads.calls, diffs.calls, paths.calls) == (0, 0, 0)


def test_a_new_scan_invalidates_the_cached_plan(estate):
    seed(estate)
    with client() as http:
        before = by_label(http.get("/v1/graph/changes").json())
        record(estate, 11, "repo-a", ["asrv", "a3", "a4"], [("asrv", "a3")])
        after = by_label(http.get("/v1/graph/changes").json())

    assert before["repo-a"]["new"]["scan_id"] == f"{TENANT}-repo-a-8"
    assert after["repo-a"]["new"]["scan_id"] == f"{TENANT}-repo-a-11"
    assert after["repo-a"]["old"]["scan_id"] == f"{TENANT}-repo-a-8"
    assert after["repo-a"]["counts"]["nodes"]["added"] == 1


def test_cached_plan_is_tenant_scoped(estate):
    seed(estate)
    record(estate, 7, "repo-z", ["zsrv"], tenant="other-tenant")
    record(estate, 8, "repo-z", ["zsrv", "z1"], tenant="other-tenant")
    with client() as http:
        mine = http.get("/v1/graph/changes").json()
    with client("other-tenant") as http:
        theirs = http.get("/v1/graph/changes").json()

    assert set(by_label(mine)) == {"repo-a", "repo-b"}
    assert set(by_label(theirs)) == {"repo-z"}
