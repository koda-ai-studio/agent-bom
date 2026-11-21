"""Demo-estate bootstrap across job TTL cleanup, restarts, refreshes and backpressure.

Each test mutates the stores or process state of its own per-test seed.
"""

from __future__ import annotations

import time

import pytest
from starlette.testclient import TestClient

from tests._demo_estate_fixtures import VIEWER, _wait_for_current_graph, demo_graph_get


def test_demo_estate_survives_job_ttl_cleanup(demo_estate_client: TestClient) -> None:
    """API job TTL must not delete curated demo-estate scan jobs."""
    from agent_bom.api import stores as api_stores
    from agent_bom.api.pipeline import _now
    from agent_bom.api.store import DEMO_ESTATE_TRIGGERED_BY
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

    store = api_stores._get_store()
    demo_jobs = [job for job in store.list_all(tenant_id=SHOWCASE_TENANT) if getattr(job, "triggered_by", None) == DEMO_ESTATE_TRIGGERED_BY]
    assert demo_jobs, "precondition: bootstrap seeded a demo-estate job"
    for job in demo_jobs:
        job.completed_at = "2020-01-01T00:00:00+00:00"
        store.put(job)

    removed = store.cleanup_expired(ttl_seconds=1)
    remaining = [job for job in store.list_all(tenant_id=SHOWCASE_TENANT) if getattr(job, "triggered_by", None) == DEMO_ESTATE_TRIGGERED_BY]
    assert remaining, f"demo estate jobs were purged by TTL (removed={removed})"

    # Restore a current completed_at so the default findings window still sees them.
    now = _now()
    for job in remaining:
        job.completed_at = now
        store.put(job)
    findings = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 1}).json()
    assert findings.get("total", 0) > 0
    # A findings read can return the previous generation while rebuilding the
    # revised jobs. Verify the new generation before fixture stores are reset.
    _wait_for_current_graph(demo_estate_client)


@pytest.mark.parametrize("durable", [False, True])
def test_demo_estate_scan_findings_restored_after_restart(
    demo_estate_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    durable: bool,
) -> None:
    """Restart retains durable jobs or re-seeds an empty in-memory job store."""
    from agent_bom.api import stores as api_stores
    from agent_bom.demo_estate.bootstrap import (
        _tenant_has_demo_jobs,
        maybe_bootstrap_demo_estate,
    )
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

    before = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 3}).json()
    assert before.get("total", 0) > 0

    # The persisted graph survives both job-store lifecycle policies.
    if not durable:
        monkeypatch.delenv("AGENT_BOM_DB")
    api_stores._store = None
    assert _tenant_has_demo_jobs(api_stores._get_store(), SHOWCASE_TENANT) is durable

    summary = maybe_bootstrap_demo_estate()
    assert summary.get("seeded") is (not durable), summary

    after = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 3}).json()
    assert after.get("total", 0) == before.get("total", 0), (before.get("total"), after.get("total"))
    _wait_for_current_graph(demo_estate_client)


# ── Enterprise estate projected into the graph ────────────────────────────
#
# Once the estate is in the graph the snapshot no longer fits one severity-ranked
# API page, so these read the whole snapshot explicitly and separately assert
# that the *default* page says so rather than reading as the estate.


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
