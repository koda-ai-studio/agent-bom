"""Durable and in-memory demo restarts each use a fresh per-test seed."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from tests._demo_estate_fixtures import VIEWER, _wait_for_current_graph


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
