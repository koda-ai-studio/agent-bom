"""Fix, rescan, detect: a changed served model shows up in the stored graph diff.

Each case runs two real CLI scans against loopback serving fixtures, stores both
graphs and reads the change back through the store and ``/v1/graph/diff``.
"""

from __future__ import annotations

import copy

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_graph_store
from tests._serving_runtime_fixtures import SCENARIOS, serving_fixture
from tests._serving_scan_helpers import scan_serving_report, serving_agent_ids, store_report

_OLD_SHA = "e985a63cdc139290c5f700ff1929f0b5942cced2"
_NEW_SHA = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c"


@pytest.fixture(autouse=True)
def _job_store(monkeypatch):
    monkeypatch.setattr(api_stores, "_store", InMemoryJobStore())


def _tgi(model_sha: str, version: str = "3.3.4") -> dict:
    routes = copy.deepcopy(SCENARIOS["tgi"]["success"])
    status, body, delay = routes[("GET", "/info")]
    routes[("GET", "/info")] = (status, {**body, "model_sha": model_sha, "version": version}, delay)
    return routes


def _rescan(tmp_path, runtime: str, before: dict, after: dict):
    """Scan one endpoint, change what it serves in place, rescan the same URL, store both graphs."""
    store = SQLiteGraphStore(tmp_path / "graph.db")
    routes = dict(before)
    with serving_fixture(routes) as url:
        first = scan_serving_report(tmp_path, [f"{runtime}={url}"])
        routes.clear()
        routes.update(after)
        second = scan_serving_report(tmp_path, [f"{runtime}={url}"])
    old = store_report(store, first, scan_id="serving-before", created_at="2026-11-01T00:00:00+00:00")
    new = store_report(store, second, scan_id="serving-after", created_at="2026-11-02T00:00:00+00:00")
    return store, old, new


def test_digest_swap_behind_the_same_name_is_a_changed_node(tmp_path):
    store, old, new = _rescan(tmp_path, "tgi", _tgi(_OLD_SHA), _tgi(_NEW_SHA))
    (node_id,) = serving_agent_ids(new).values()
    assert serving_agent_ids(old) == serving_agent_ids(new)

    diff = store.diff_snapshots("serving-before", "serving-after", tenant_id="default")
    assert node_id in diff["nodes_changed"]
    deltas = {delta["field"]: delta for delta in diff["attribute_deltas"][node_id]}
    assert deltas["serving_evidence.model.digest"]["before"] == _OLD_SHA
    assert deltas["serving_evidence.model.digest"]["after"] == _NEW_SHA
    assert deltas["serving_evidence.model.digest"]["summary"] == "Served model digest changed"
    assert "serving_evidence.runtime.version" not in deltas


def test_runtime_upgrade_is_reported_separately_from_the_model(tmp_path):
    store, _old, new = _rescan(tmp_path, "tgi", _tgi(_OLD_SHA, "3.3.4"), _tgi(_OLD_SHA, "3.4.0"))
    (node_id,) = serving_agent_ids(new).values()
    deltas = {delta["field"]: delta for delta in store.diff_snapshots("serving-before", "serving-after")["attribute_deltas"][node_id]}
    assert set(deltas) == {"serving_evidence.runtime.version"}
    assert (deltas["serving_evidence.runtime.version"]["before"], deltas["serving_evidence.runtime.version"]["after"]) == ("3.3.4", "3.4.0")


def test_unchanged_rescan_reports_no_serving_change(tmp_path):
    store, _old, new = _rescan(tmp_path, "tgi", _tgi(_OLD_SHA), _tgi(_OLD_SHA))
    (node_id,) = serving_agent_ids(new).values()
    diff = store.diff_snapshots("serving-before", "serving-after")
    assert node_id not in diff["nodes_changed"]
    assert node_id not in diff["attribute_deltas"]


def test_replaced_served_model_is_removed_and_added(tmp_path):
    before = SCENARIOS["vllm"]["success"]
    after = copy.deepcopy(before)
    status, body, delay = after[("GET", "/v1/models")]
    replacement = {**body["data"][0], "id": "llama-3.2-1b-instruct", "root": "meta-llama/Llama-3.2-1B-Instruct"}
    after[("GET", "/v1/models")] = (status, {**body, "data": [replacement]}, delay)
    store, old, new = _rescan(tmp_path, "vllm", before, after)
    (old_id,) = serving_agent_ids(old).values()
    (new_id,) = serving_agent_ids(new).values()
    assert old_id != new_id

    original = api_stores._graph_store
    set_graph_store(store)
    try:
        body = TestClient(app).get("/v1/graph/diff", params={"old": "serving-before", "new": "serving-after", "view": "full"}).json()
    finally:
        set_graph_store(original)
    index = body["change_kind_index"]["nodes"]
    assert index[old_id] == "removed"
    assert index[new_id] == "new"


def test_digest_change_reaches_the_graph_diff_api(tmp_path):
    store, _old, new = _rescan(tmp_path, "tgi", _tgi(_OLD_SHA), _tgi(_NEW_SHA))
    (node_id,) = serving_agent_ids(new).values()
    original = api_stores._graph_store
    set_graph_store(store)
    try:
        body = TestClient(app).get("/v1/graph/diff", params={"old": "serving-before", "new": "serving-after", "view": "full"}).json()
    finally:
        set_graph_store(original)
    assert body["change_kind_index"]["nodes"][node_id] == "changed"
    assert [delta["field"] for delta in body["attribute_deltas"][node_id]] == ["serving_evidence.model.digest"]
