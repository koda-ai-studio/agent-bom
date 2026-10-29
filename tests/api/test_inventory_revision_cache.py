"""``/v1/inventory`` reuses the revision-keyed scanned-estate projection instead of re-parsing every job."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api import agent_evidence, stores
from agent_bom.api.agent_evidence import clear_agent_evidence_cache
from agent_bom.api.server import app
from agent_bom.api.store import SQLiteJobStore
from tests.api.test_scan_job_sla_history import job
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

TENANT = "inventory-tenant"


@pytest.fixture
def jobs(tmp_path, monkeypatch):
    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    monkeypatch.setattr(stores, "_store", store)
    clear_agent_evidence_cache()
    enable_trusted_proxy_env()
    yield store
    disable_trusted_proxy_env()
    clear_agent_evidence_cache()


def _scan(month: int, agent: str, *, tenant: str = TENANT, target: str = "repo-a"):
    row = job(month, tenant=tenant, target=target, findings=[])
    row.result["agents"] = [
        {
            "name": agent,
            "canonical_id": f"agent-{agent}",
            "agent_type": "custom",
            "mcp_servers": [{"name": "srv", "packages": [{"name": f"{agent}-pkg", "version": "1.0.0", "ecosystem": "npm"}]}],
        }
    ]
    return row


def _get(tenant: str = TENANT) -> dict:
    with TestClient(app, headers=proxy_headers(tenant=tenant)) as client:
        response = client.get("/v1/inventory")
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize("background_read", [None, "all-tenants", "same-tenant"])
def test_repeat_inventory_read_does_not_reparse_jobs(jobs, monkeypatch, background_read):
    jobs.put(_scan(8, "alpha"))
    calls = []
    original = agent_evidence.build_agent_evidence

    def count_inventory_projection(rows):
        # Campaign workers may independently read this same store and tenant.
        # Measure the scanned-estate projection, not every background DB read.
        rows = list(rows)
        if any(row.tenant_id == TENANT for row in rows):
            calls.append(1)
        return original(rows)

    monkeypatch.setattr(agent_evidence, "build_agent_evidence", count_inventory_projection)
    first = _get()
    assert calls == [1], "the cold request must build the projection exactly once"
    calls.clear()

    if background_read == "all-tenants":
        # A lifecycle worker can read the store while this request is served.
        jobs.list_all(all_tenants=True)
    elif background_read == "same-tenant":
        jobs.list_all(tenant_id=TENANT)
    second = _get()

    assert second == first
    assert calls == []
    assert [agent["name"] for agent in second["agents"]] == ["alpha"]
    assert [row["job_id"] for row in second["jobs"]] == [f"{TENANT}-repo-a-8"]


def test_a_new_scan_moves_the_inventory(jobs):
    jobs.put(_scan(8, "alpha"))
    assert [agent["name"] for agent in _get()["agents"]] == ["alpha"]
    jobs.put(_scan(9, "beta", target="repo-b"))

    body = _get()

    assert sorted(agent["name"] for agent in body["agents"]) == ["alpha", "beta"]
    assert body["job_total"] == 2
    assert {package["name"] for package in body["packages"]} == {"alpha-pkg", "beta-pkg"}


def test_inventory_projection_is_tenant_scoped(jobs):
    jobs.put(_scan(8, "alpha"))
    jobs.put(_scan(8, "intruder", tenant="other-tenant"))

    assert [agent["name"] for agent in _get()["agents"]] == ["alpha"]
    assert [agent["name"] for agent in _get("other-tenant")["agents"]] == ["intruder"]
