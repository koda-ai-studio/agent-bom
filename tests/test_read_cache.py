"""Bounded per-process response cache for expensive tenant reads."""

from __future__ import annotations

import threading
import time

import pytest
from starlette.requests import Request

from agent_bom.api import read_cache
from agent_bom.api.routes.compliance_routes import common


@pytest.fixture(autouse=True)
def _clean_cache():
    read_cache.clear_read_cache()
    yield
    read_cache.clear_read_cache()


def _counter():
    calls = {"n": 0}

    def compute() -> dict:
        calls["n"] += 1
        return {"n": calls["n"], "nested": {"items": [1, 2]}}

    return calls, compute


def test_same_generation_serves_cached_body_once_computed():
    calls, compute = _counter()
    first = read_cache.cached_read("posture", "acme", (), compute, generation="g1")
    second = read_cache.cached_read("posture", "acme", (), compute, generation="g1")
    assert first == second == {"n": 1, "nested": {"items": [1, 2]}}
    assert calls["n"] == 1


def test_generation_bump_invalidates_cached_body():
    calls, compute = _counter()
    assert read_cache.cached_read("posture", "acme", (), compute, generation="g1")["n"] == 1
    assert read_cache.cached_read("posture", "acme", (), compute, generation="g2")["n"] == 2
    # The retired generation is never served again, even if asked for.
    assert read_cache.cached_read("posture", "acme", (), compute, generation="g1")["n"] == 3
    assert calls["n"] == 3


def test_query_params_and_kind_are_part_of_the_key():
    calls, compute = _counter()
    read_cache.cached_read("compliance", "acme", (("scan_id", None),), compute, generation="g1")
    read_cache.cached_read("compliance", "acme", (("scan_id", "s-1"),), compute, generation="g1")
    read_cache.cached_read("posture", "acme", (("scan_id", None),), compute, generation="g1")
    assert calls["n"] == 3


def test_tenants_never_share_an_entry():
    calls, compute = _counter()
    a = read_cache.cached_read("posture", "tenant-a", (), compute, generation="g1")
    b = read_cache.cached_read("posture", "tenant-b", (), compute, generation="g1")
    assert a["n"] == 1 and b["n"] == 2
    assert calls["n"] == 2


def test_unknown_generation_bypasses_the_cache():
    calls, compute = _counter()
    read_cache.cached_read("posture", "acme", (), compute, generation=None)
    read_cache.cached_read("posture", "acme", (), compute, generation=None)
    assert calls["n"] == 2
    assert read_cache.read_cache_size() == 0


def test_errors_are_never_cached():
    attempts = {"n": 0}

    def flaky() -> dict:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise RuntimeError("store unavailable")
        return {"ok": True}

    with pytest.raises(RuntimeError):
        read_cache.cached_read("posture", "acme", (), flaky, generation="g1")
    assert read_cache.read_cache_size() == 0
    assert read_cache.cached_read("posture", "acme", (), flaky, generation="g1") == {"ok": True}
    assert attempts["n"] == 2


def test_ttl_expiry_recomputes(monkeypatch):
    calls, compute = _counter()
    now = {"t": 1000.0}
    monkeypatch.setattr(read_cache.time, "monotonic", lambda: now["t"])
    read_cache.cached_read("posture", "acme", (), compute, generation="g1", ttl=60.0)
    now["t"] += 59.0
    read_cache.cached_read("posture", "acme", (), compute, generation="g1", ttl=60.0)
    assert calls["n"] == 1
    now["t"] += 2.0
    read_cache.cached_read("posture", "acme", (), compute, generation="g1", ttl=60.0)
    assert calls["n"] == 2


def test_entries_are_bounded_lru():
    _calls, compute = _counter()
    for i in range(read_cache.READ_CACHE_MAX_ENTRIES + 10):
        read_cache.cached_read("posture", f"tenant-{i}", (), compute, generation="g1")
    assert read_cache.read_cache_size() == read_cache.READ_CACHE_MAX_ENTRIES
    # The oldest tenant was evicted and recomputes; the newest is still served.
    calls, compute2 = _counter()
    read_cache.cached_read("posture", "tenant-0", (), compute2, generation="g1")
    assert calls["n"] == 1
    read_cache.cached_read("posture", f"tenant-{read_cache.READ_CACHE_MAX_ENTRIES + 9}", (), compute2, generation="g1")
    assert calls["n"] == 1


def test_hits_return_independent_copies():
    _calls, compute = _counter()
    first = read_cache.cached_read("posture", "acme", (), compute, generation="g1")
    first["nested"]["items"].append(99)
    second = read_cache.cached_read("posture", "acme", (), compute, generation="g1")
    assert second["nested"]["items"] == [1, 2]


def test_concurrent_misses_on_one_key_compute_once():
    calls = {"n": 0}
    lock = threading.Lock()

    def slow() -> dict:
        with lock:
            calls["n"] += 1
        time.sleep(0.05)
        return {"ok": True}

    results: list[dict] = []

    def worker() -> None:
        results.append(read_cache.cached_read("posture", "acme", (), slow, generation="g1"))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert calls["n"] == 1
    assert results == [{"ok": True}] * 6


def test_disabled_by_zero_ttl_env(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_READ_CACHE_TTL_SECONDS", "0")
    calls, compute = _counter()
    read_cache.cached_read("posture", "acme", (), compute, generation="g1")
    read_cache.cached_read("posture", "acme", (), compute, generation="g1")
    assert calls["n"] == 2


def test_evidence_generation_is_none_without_a_revision_capable_job_store(monkeypatch):
    class _NoRevisionStore:
        pass

    monkeypatch.setattr(common, "_get_store", lambda: _NoRevisionStore())
    assert common.evidence_generation("acme") is None


def test_evidence_generation_changes_with_each_input(monkeypatch):
    revisions = {"jobs": "db1:1", "hub": 1, "suppressions": "s1", "graph": "scan-1", "graph_revision": "r1"}

    class _Store:
        def overview_evidence_revision(self, tenant_id: str) -> str:
            assert tenant_id == "acme"
            return revisions["jobs"]

    class _Hub:
        def overview_evidence_revision(self, tenant_id: str) -> int:
            return revisions["hub"]

    class _Graph:
        def snapshot_identity(self, *, tenant_id: str, scan_id: str = "", for_paging: bool = False) -> tuple[str, str]:
            assert tenant_id == "acme" and for_paging
            return revisions["graph"], revisions["graph_revision"]

    monkeypatch.setattr(common, "_get_store", lambda: _Store())
    monkeypatch.setattr(common, "_hub_store", lambda: _Hub())
    monkeypatch.setattr(common, "_get_graph_store", lambda: _Graph())
    monkeypatch.setattr(common, "suppression_revision", lambda tenant_id: revisions["suppressions"])
    seen = {common.evidence_generation("acme")}
    for key, value in (("jobs", "db1:2"), ("hub", 2), ("suppressions", "s2"), ("graph", "scan-2"), ("graph_revision", "r2")):
        revisions[key] = value
        seen.add(common.evidence_generation("acme"))
    assert len(seen) == 6
    assert None not in seen


def test_compliance_cache_tracks_the_selected_snapshot(monkeypatch):
    seen = []

    def generation(tenant_id, *, scan_id=""):
        seen.append((tenant_id, scan_id))
        return "g1"

    monkeypatch.setattr(common, "evidence_generation", generation)

    @common.cached_compliance_snapshot
    def reader(request, scan_id):
        return {"scan_id": scan_id}

    request = Request({"type": "http", "state": {"tenant_id": "acme"}})
    assert reader(request, "historic")["scan_id"] == "historic"
    assert seen == [("acme", "historic")]


def test_cached_tenant_read_keys_on_request_tenant(monkeypatch):
    monkeypatch.setattr(common, "evidence_generation", lambda tenant_id, **kwargs: f"gen-{tenant_id}")
    calls, compute = _counter()
    req_a = Request({"type": "http", "state": {"tenant_id": "acme"}})
    req_b = Request({"type": "http", "state": {"tenant_id": "globex"}})
    common.cached_tenant_read(req_a, "posture", (), compute)
    common.cached_tenant_read(req_a, "posture", (), compute)
    common.cached_tenant_read(req_b, "posture", (), compute)
    assert calls["n"] == 2


def test_get_put_primitives_follow_generation_and_ttl():
    params = (("scan_id", ""), ("limit", 8))
    assert read_cache.read_cache_get("fix_first_view", "acme", params, generation="g1") is None
    read_cache.read_cache_put("fix_first_view", "acme", params, {"paths": [1]}, generation="g1")
    assert read_cache.read_cache_get("fix_first_view", "acme", params, generation="g1") == {"paths": [1]}
    assert read_cache.read_cache_get("fix_first_view", "acme", params, generation="g2") is None
    assert read_cache.read_cache_get("fix_first_view", "acme", (("scan_id", ""), ("limit", 9)), generation="g1") is None
    read_cache.read_cache_put("fix_first_view", "acme", params, {"paths": [2]}, generation=None)
    assert read_cache.read_cache_size() == 0


def test_cached_compliance_snapshot_reuses_the_body_until_the_generation_moves(monkeypatch):
    generation = {"value": "g1"}
    monkeypatch.setattr(common, "evidence_generation", lambda tenant_id, **kwargs: generation["value"])
    calls = {"n": 0}

    @common.cached_compliance_snapshot
    def reader(request: Request, scan_id: str | None) -> dict:
        calls["n"] += 1
        return {"scan_id": scan_id, "n": calls["n"]}

    req = Request({"type": "http", "state": {"tenant_id": "acme"}})
    assert reader(req, None)["n"] == 1
    assert reader(req, None)["n"] == 1
    assert reader(req, "scan-1")["n"] == 2
    generation["value"] = "g2"
    assert reader(req, None)["n"] == 3
