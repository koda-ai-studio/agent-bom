"""A demo-estate server never admits real evidence into the labeled demo tenant.

Demo mode serves a synthetic estate under the showcase tenant and labels it
"Demo data". Evidence pushed or collected into that tenant would render under
the same label, so every ingest operation fails closed for it, whatever the
caller's role. Other tenants on the same server stay writable.
"""

from __future__ import annotations

import re

import pytest
from starlette.testclient import TestClient

from agent_bom.api.demo_tenant_guard import DEMO_TENANT_INGEST_OPERATIONS, NON_INGEST_WRITE_OPERATIONS, demo_tenant_ingest_rejection
from agent_bom.demo_estate.showcase_constants import SHOWCASE_TENANT
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def _concrete(template: str) -> str:
    return re.sub(r"\{[^}]+\}", "fixture-id", template)


@pytest.fixture
def demo_mode(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    enable_trusted_proxy_env()
    from agent_bom.api.server import set_job_store
    from agent_bom.api.store import InMemoryJobStore

    store = InMemoryJobStore()
    set_job_store(store)
    yield store
    disable_trusted_proxy_env()


@pytest.mark.parametrize(("method", "template"), sorted(DEMO_TENANT_INGEST_OPERATIONS))
def test_every_ingest_operation_is_rejected_for_the_demo_tenant(monkeypatch, method, template):
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    rejection = demo_tenant_ingest_rejection(method, _concrete(template), SHOWCASE_TENANT)
    assert rejection is not None
    assert rejection.status_code == 409


@pytest.mark.parametrize(("method", "template"), sorted(DEMO_TENANT_INGEST_OPERATIONS))
def test_ingest_is_untouched_outside_demo_mode_or_for_other_tenants(monkeypatch, method, template):
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    assert demo_tenant_ingest_rejection(method, _concrete(template), SHOWCASE_TENANT) is None
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    assert demo_tenant_ingest_rejection(method, _concrete(template), "tenant-real") is None


def test_reads_and_unrelated_paths_stay_open_in_demo_mode(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    assert demo_tenant_ingest_rejection("GET", "/v1/results/push", SHOWCASE_TENANT) is None
    assert demo_tenant_ingest_rejection("GET", "/v1/scan/abc", SHOWCASE_TENANT) is None
    assert demo_tenant_ingest_rejection("POST", "/v1/scan/check", SHOWCASE_TENANT) is None
    assert demo_tenant_ingest_rejection("POST", "/v1/results/push-extra", SHOWCASE_TENANT) is None


def test_results_push_to_demo_tenant_is_refused_and_nothing_is_stored(demo_mode):
    from agent_bom.api.server import app

    client = TestClient(app)
    body = {"source_id": "real-laptop", "agents": [{"name": "real-agent", "type": "custom", "mcp_servers": []}]}
    refused = client.post("/v1/results/push", json=body, headers=proxy_headers(role="admin", tenant=SHOWCASE_TENANT))
    assert refused.status_code == 409, refused.text
    detail = refused.json()["detail"]
    assert "demo" in detail.lower()
    assert "Traceback" not in detail
    assert demo_mode.list_all(tenant_id=SHOWCASE_TENANT) == []

    accepted = client.post("/v1/results/push", json=body, headers=proxy_headers(role="admin", tenant="tenant-real"))
    assert accepted.status_code == 201, accepted.text


@pytest.mark.parametrize(("method", "template"), sorted(DEMO_TENANT_INGEST_OPERATIONS))
def test_each_guarded_route_answers_409_over_http(demo_mode, method, template):
    from agent_bom.api.server import app

    client = TestClient(app, raise_server_exceptions=False)
    response = client.request(method, _concrete(template), json={}, headers=proxy_headers(role="admin", tenant=SHOWCASE_TENANT))
    assert response.status_code == 409, (template, response.status_code, response.text[:200])


_INGEST_SHAPED = re.compile(r"push|ingest|sync|/scan|/run|traces|events|audit|collect|pull", re.I)


def _app_write_operations() -> set[tuple[str, str]]:
    from fastapi.routing import iter_route_contexts

    from agent_bom.api.server import app

    return {
        (method, ctx.path)
        for ctx in iter_route_contexts(app.routes)
        for method in (getattr(ctx.route, "methods", None) or set())
        if method in {"POST", "PUT", "PATCH"}
    }


def test_every_ingest_shaped_write_route_is_classified():
    """A new ingest route must be guarded or explicitly declared not to ingest evidence."""
    classified = DEMO_TENANT_INGEST_OPERATIONS | NON_INGEST_WRITE_OPERATIONS
    unclassified = sorted(op for op in _app_write_operations() if _INGEST_SHAPED.search(op[1]) and op not in classified)
    assert unclassified == []


def test_guard_table_names_only_mounted_routes():
    mounted = _app_write_operations()
    stale = sorted((DEMO_TENANT_INGEST_OPERATIONS | NON_INGEST_WRITE_OPERATIONS) - mounted)
    assert stale == []
