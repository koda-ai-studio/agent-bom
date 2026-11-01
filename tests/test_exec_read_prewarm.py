"""Exec reads are warmed off the request path after a push or seed, bounded and coalesced."""

from __future__ import annotations

import threading
import time

import pytest

from agent_bom.api import exec_read_prewarm as prewarm


@pytest.fixture(autouse=True)
def _reset():
    with prewarm._LOCK:
        prewarm._PENDING.clear()
        prewarm._WORKER = None
    yield
    with prewarm._LOCK:
        prewarm._PENDING.clear()
        prewarm._WORKER = None


def _wait_idle(timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with prewarm._LOCK:
            idle = prewarm._WORKER is None and not prewarm._PENDING
        if idle:
            return
        time.sleep(0.01)
    raise AssertionError("prewarm worker did not drain")


def test_warms_every_exec_read_with_a_tenant_bound_internal_request(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[str, str, str, dict]] = []

    def fake(name: str):
        async def endpoint(request, **params):  # noqa: ANN001, ANN202
            seen.append((name, request.state.tenant_id, request.state.auth_method, params))
            return {"ok": True}

        endpoint.__name__ = name
        return endpoint

    monkeypatch.setattr(prewarm, "EXEC_READS", tuple((fake(n), p, q) for (f, p, q) in prewarm.EXEC_READS for n in [f.__name__]))
    scheduled = prewarm.schedule_exec_prewarm("acme")
    assert scheduled is True
    _wait_idle()
    names = [row[0] for row in seen]
    assert names == ["get_posture_counts", "get_compliance_summary", "get_fix_first_graph_view", "get_executive_brief"]
    assert all(row[1] == "acme" and row[2] == "prewarm" for row in seen), "every warm read is tenant-bound and marked internal"
    assert seen[3][3] == {"limit": 5}


def test_repeat_schedules_coalesce_and_one_failing_read_does_not_stop_the_rest(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    started, gate = threading.Event(), threading.Event()

    async def slow_ok(request, **params):  # noqa: ANN001, ANN202
        started.set()
        gate.wait(2.0)
        calls.append("ok:" + request.state.tenant_id)
        return {}

    async def boom(request, **params):  # noqa: ANN001, ANN202
        calls.append("boom:" + request.state.tenant_id)
        raise RuntimeError("store offline")

    slow_ok.__name__, boom.__name__ = "slow_ok", "boom"
    monkeypatch.setattr(prewarm, "EXEC_READS", ((slow_ok, "/a", {}), (boom, "/b", {}), (slow_ok, "/c", {})))
    prewarm.schedule_exec_prewarm("busy")
    assert started.wait(2.0), "worker picked up the first tenant"
    for _ in range(5):
        prewarm.schedule_exec_prewarm("acme")
    prewarm.schedule_exec_prewarm("other")
    assert prewarm.pending_exec_prewarms() == {"acme", "other"}
    gate.set()
    _wait_idle()
    # Five queued schedules for one tenant ran once; the failing read was skipped, the one after it still ran.
    for tenant in ("busy", "acme", "other"):
        assert calls.count(f"boom:{tenant}") == 1 and calls.count(f"ok:{tenant}") == 2, tenant


def test_a_push_during_a_running_warm_up_queues_one_more(monkeypatch: pytest.MonkeyPatch) -> None:
    runs: list[str] = []
    started, gate = threading.Event(), threading.Event()

    async def read(request, **params):  # noqa: ANN001, ANN202
        runs.append(request.state.tenant_id)
        started.set()
        gate.wait(2.0)
        return {}

    monkeypatch.setattr(prewarm, "EXEC_READS", ((read, "/a", {}),))
    prewarm.schedule_exec_prewarm("acme")
    assert started.wait(2.0)
    # The running warm-up read the old generation; the new push must be warmed once more, not dropped.
    prewarm.schedule_exec_prewarm("acme")
    prewarm.schedule_exec_prewarm("acme")
    gate.set()
    _wait_idle()
    assert runs == ["acme", "acme"]


def test_disabled_by_env_and_empty_tenant_never_schedule(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_EXEC_PREWARM", "0")
    assert prewarm.schedule_exec_prewarm("acme") is False
    monkeypatch.delenv("AGENT_BOM_EXEC_PREWARM")
    assert prewarm.schedule_exec_prewarm("") is False
    assert prewarm.pending_exec_prewarms() == set()


def test_real_exec_routes_accept_the_warm_request_and_fill_the_dashboard_cache_keys(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    import asyncio

    from agent_bom.api import read_cache
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.store import SQLiteJobStore
    from agent_bom.api.stores import set_graph_store, set_job_store
    from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode

    tenant = "prewarm-tenant"
    store = SQLiteGraphStore(tmp_path / "graph.db")
    graph = UnifiedGraph(scan_id="warm-scan", tenant_id=tenant)
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
    graph.add_node(UnifiedNode(id="server:a:fs", entity_type=EntityType.SERVER, label="mcp-fs"))
    graph.add_node(UnifiedNode(id="vuln:CVE-2024-1", entity_type=EntityType.VULNERABILITY, label="CVE-2024-1", severity="critical"))
    graph.add_edge(UnifiedEdge(source="agent:a", target="server:a:fs", relationship=RelationshipType.USES))
    graph.add_edge(UnifiedEdge(source="server:a:fs", target="vuln:CVE-2024-1", relationship=RelationshipType.VULNERABLE_TO))
    store.save_graph(graph)
    set_graph_store(store)
    set_job_store(SQLiteJobStore(str(tmp_path / "jobs.db")))
    read_cache.clear_read_cache()
    try:
        outcome = asyncio.run(prewarm.warm_exec_reads(tenant))
        assert outcome == dict.fromkeys(
            ("get_posture_counts", "get_compliance_summary", "get_fix_first_graph_view", "get_executive_brief"), True
        )
        with read_cache._LOCK:
            kinds = {key[0] for key in read_cache._CACHE if key[1] == tenant}
            foreign = [key for key in read_cache._CACHE if key[1] != tenant]
        assert {"fix_first_view", "compliance"} <= kinds, kinds
        assert not foreign, "a warm-up for one tenant never fills another tenant's keys"
    finally:
        read_cache.clear_read_cache()
