"""Unpinned findings and fleet reads refuse while the demo seed lands, like current-estate graph reads."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent_bom.api import auth
from agent_bom.api.middleware import APIKeyMiddleware, TrustHeadersMiddleware
from agent_bom.api.routes import fleet as fleet_routes
from agent_bom.api.routes import scan as scan_routes
from tests.test_current_estate_seeding_refusal import TENANT, seeding  # noqa: F401 - pytest fixture

UNPINNED = [("/v1/findings", {}), ("/v1/findings", {"limit": 5, "sort": "severity"}), ("/v1/fleet", {}), ("/v1/fleet/stats", {})]


@pytest.fixture()
def client(monkeypatch):
    from agent_bom.backpressure import reset_backpressure_for_tests

    reset_backpressure_for_tests()
    monkeypatch.delenv("AGENT_BOM_MCP_TENANT_ID", raising=False)
    monkeypatch.delenv("AGENT_BOM_TENANT_ID", raising=False)
    keys = auth.KeyStore()
    monkeypatch.setattr(auth, "_key_store", keys)
    token, key = auth.create_api_key(TENANT, auth.Role.VIEWER, tenant_id=TENANT)
    keys.add(key)
    app = FastAPI()
    app.include_router(scan_routes.router, prefix="/v1")
    app.include_router(fleet_routes.router, prefix="/v1")
    app.add_middleware(APIKeyMiddleware, api_key="", allow_unauthenticated=False)
    app.add_middleware(TrustHeadersMiddleware)
    with TestClient(app, headers={"Authorization": f"Bearer {token}"}) as test_client:
        yield test_client
    reset_backpressure_for_tests()


@pytest.mark.parametrize(("path", "params"), UNPINNED, ids=[f"{p} {sorted(q)}" for p, q in UNPINNED])
def test_unpinned_read_refuses_while_seeding_then_serves(client, seeding, path, params):  # noqa: F811
    refused = client.get(path, params=params)
    assert refused.status_code == 503, refused.text
    assert refused.headers["Retry-After"] == "2"
    assert refused.json()["detail"]["code"] == "current_estate_seeding"

    seeding._boot_seed_done.set()
    assert client.get(path, params=params).status_code == 200


def test_findings_pinned_to_a_scan_are_not_refused(client, seeding):  # noqa: F811
    pinned = client.get("/v1/findings", params={"scan_id": "some-recorded-scan"})
    assert pinned.status_code != 503, pinned.text


def test_a_seed_for_another_tenant_does_not_refuse_this_one(client, seeding, monkeypatch):  # noqa: F811
    seeding._boot_seed_done.set()
    monkeypatch.setattr(seeding, "_persisted_seed_active", lambda tenant_id: tenant_id in (None, "other-tenant"))
    assert client.get("/v1/findings").status_code == 200
    assert client.get("/v1/fleet").status_code == 200
