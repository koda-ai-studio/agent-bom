"""Readiness and cross-process fixture state must agree on one finished seed."""

from types import SimpleNamespace

from agent_bom.demo_estate import boot_seed, bootstrap


def test_readiness_is_published_after_shared_seed_marker_clears(monkeypatch):
    from agent_bom.api import posture_counts_cache

    visible_at_ready = []
    monkeypatch.setattr(bootstrap, "maybe_bootstrap_demo_estate", lambda: None)
    monkeypatch.setattr(posture_counts_cache, "wait_for_posture_precompute", lambda timeout: True)
    monkeypatch.setattr(
        boot_seed,
        "_boot_seed_done",
        SimpleNamespace(set=lambda: visible_at_ready.append(boot_seed._persisted_seed_active("default"))),
    )
    boot_seed._run_boot_seed()
    assert visible_at_ready == [False], "readiness allowed a caller to race the shared seeding refusal"


def test_seed_fixture_ignores_unrelated_retained_scan_jobs(tmp_path, monkeypatch):
    from agent_bom.api import stores
    from agent_bom.api.store import InMemoryJobStore
    from tests.api.test_scan_job_sla_history import job
    from tests.test_demo_seed_cross_process import _mcp_exposure, store

    stale = InMemoryJobStore()
    previous = job(8, tenant="default", target="unrelated-checkout", findings=[])
    previous.result["scan_id"] = previous.job_id
    stale.put(previous)
    monkeypatch.setattr(stores, "_store", stale)
    fixture = store.__wrapped__(tmp_path, monkeypatch)
    next(fixture)
    try:
        served = _mcp_exposure()
        assert "error" not in served and served["paths"], served
    finally:
        fixture.close()
