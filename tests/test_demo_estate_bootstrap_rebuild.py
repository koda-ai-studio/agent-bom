"""The maintenance tick must not rebuild the enterprise estate once it is seeded.

``_cleanup_tick`` calls ``maybe_bootstrap_demo_estate`` every minute. Building
and validating the composed enterprise estate is the expensive part, so a seed
that is complete for the current estate version returns before it; a version
change, a lost scan job or a stale graph still reseed.
"""

from __future__ import annotations

import asyncio

import pytest
from starlette.testclient import TestClient

from agent_bom.demo_estate import enterprise_composition
from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate


@pytest.fixture
def build_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    real = enterprise_composition.build_demo_estate

    def spy(*args, **kwargs):
        calls.append(kwargs.get("tenant_id", ""))
        return real(*args, **kwargs)

    monkeypatch.setattr(enterprise_composition, "build_demo_estate", spy)
    return calls


def test_cleanup_tick_does_not_rebuild_a_current_estate(demo_estate_client: TestClient, build_calls: list[str]) -> None:
    from agent_bom.api.server import _cleanup_tick

    asyncio.run(_cleanup_tick())
    asyncio.run(_cleanup_tick())

    assert build_calls == []
    summary = maybe_bootstrap_demo_estate()
    assert build_calls == []
    assert summary["reason"] == "demo_jobs_present" and summary["rebuild_skipped"] is True
    assert summary["enterprise_contract"]["content_hash"]


def test_changed_estate_version_reseeds(
    demo_estate_client: TestClient,
    build_calls: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_bom.demo_estate import bootstrap

    monkeypatch.setattr(bootstrap, "DEMO_ESTATE_SEED_MARKER", ("changed",))
    summary = maybe_bootstrap_demo_estate()

    assert len(build_calls) == 1
    assert "rebuild_skipped" not in summary
    assert summary["estate_seed_marker"] == ["changed"]
    maybe_bootstrap_demo_estate()
    assert len(build_calls) == 1


def test_lost_demo_job_reseeds(demo_estate_client: TestClient, build_calls: list[str]) -> None:
    from agent_bom.api import stores as api_stores
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

    store = api_stores._get_store()
    for job in list(store.list_all(tenant_id=SHOWCASE_TENANT)):
        store.delete(job.job_id, tenant_id=SHOWCASE_TENANT)

    summary = maybe_bootstrap_demo_estate()

    assert build_calls and summary["seeded"] is True
