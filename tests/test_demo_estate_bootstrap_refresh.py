"""Demo refresh and backpressure each use a fresh per-test seed."""

from __future__ import annotations

import time

from tests._demo_estate_fixtures import demo_graph_get


def test_demo_topology_reader_honors_bounded_backpressure(demo_estate_client):
    from agent_bom.backpressure import _controller_for

    controller = _controller_for("graph")
    controller.open_until_monotonic = time.monotonic() + 1
    controller.last_trigger_reason = "p99_latency_threshold"
    response = demo_graph_get(demo_estate_client, "/v1/graph", {"limit": 1})
    assert response.status_code == 200, response.text
    assert controller.rejected >= 1


def test_refreshed_demo_graph_gets_matching_scan_evidence(demo_estate_client, monkeypatch):
    from agent_bom.api.server import _cleanup_tick
    from agent_bom.api.stores import _get_store
    from agent_bom.demo_estate import bootstrap

    store = _get_store()
    before = store.list_all(tenant_id="default")
    report = next(job.result for job in before if job.result and bootstrap._job_has_demo_source(job))
    monkeypatch.setattr(bootstrap, "seed_showcase_graph_if_empty", lambda *args, **kwargs: True)
    monkeypatch.setattr(bootstrap, "_run_demo_scan_report", lambda **kwargs: report)
    # A refresh requires stale graph evidence; a current estate now returns
    # before the expensive seeder. Model the precondition as well as its write.
    with monkeypatch.context() as stale_graph:
        stale_graph.setattr(bootstrap, "_showcase_seed_is_current", lambda _snapshots: False)
        refreshed = bootstrap.maybe_bootstrap_demo_estate(tenant_id="default")
    assert refreshed["seeded"] is True
    assert len(store.list_all(tenant_id="default")) == len(before) + 1
    monkeypatch.setattr(bootstrap, "seed_showcase_graph_if_empty", lambda *args, **kwargs: False)
    assert bootstrap.maybe_bootstrap_demo_estate(tenant_id="default")["reason"] == "demo_jobs_present"
    assert len(store.list_all(tenant_id="default")) == len(before) + 1
    # A real maintenance pass must preserve the already-refreshed evidence.
    demo_estate_client.portal.call(_cleanup_tick)
    assert len(store.list_all(tenant_id="default")) == len(before) + 1
