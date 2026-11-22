"""Demo-estate job TTL cleanup uses its own fresh per-test seed."""

from __future__ import annotations

from starlette.testclient import TestClient

from tests._demo_estate_fixtures import VIEWER, _wait_for_current_graph


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
