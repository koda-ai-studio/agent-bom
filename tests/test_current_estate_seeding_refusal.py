"""Every unpinned current-estate read refuses while the demo seed lands; none answers empty-and-complete."""

from __future__ import annotations

import asyncio
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent_bom.api import auth, stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.middleware import APIKeyMiddleware, TrustHeadersMiddleware
from agent_bom.api.routes import graph as graph_routes
from agent_bom.api.routes import inventory_assets
from tests.test_graph_tenant_scope_and_bounds import _path_graph

TENANT = "tenant-a"
NODE = "principal:reader"

UNPINNED_READS = [
    ("GET", "/v1/graph", {}, None),
    ("GET", "/v1/graph/attack-paths", {}, None),
    ("GET", "/v1/graph/attack-paths/cross-vendor", {}, None),
    ("GET", "/v1/graph/exposure-paths", {}, None),
    ("GET", "/v1/graph/search", {"q": "reader"}, None),
    ("GET", "/v1/graph/agents", {}, None),
    ("GET", "/v1/graph/paths", {"source_id": NODE}, None),
    ("GET", "/v1/graph/rollup", {}, None),
    ("GET", "/v1/graph/compliance", {}, None),
    ("GET", "/v1/graph/clusters", {}, None),
    ("GET", "/v1/graph/governance", {}, None),
    ("GET", "/v1/graph/nhi/governance", {}, None),
    ("GET", "/v1/graph/evidence-manifest", {}, None),
    ("GET", "/v1/graph/views/fix-first", {}, None),
    ("GET", "/v1/graph/node-context", {"node_id": NODE}, None),
    ("GET", f"/v1/graph/node/{NODE}", {}, None),
    ("GET", "/v1/graph/node-neighbors", {"node_id": NODE}, None),
    ("GET", "/v1/graph/impact", {"node": NODE}, None),
    ("GET", "/v1/graph/incident-edges", {"node_id": NODE}, None),
    ("POST", "/v1/graph/query", {}, {"roots": [NODE]}),
    ("POST", "/v1/graph/should-i-deploy", {}, {"candidate": NODE}),
    ("GET", "/v1/inventory/assets", {}, None),
    ("GET", "/v1/inventory/summary", {}, None),
]


@pytest.fixture()
def seeding(monkeypatch):
    from agent_bom.demo_estate import boot_seed

    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    boot_seed._boot_seed_done.clear()
    yield boot_seed
    boot_seed._boot_seed_done.set()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from agent_bom.backpressure import reset_backpressure_for_tests

    reset_backpressure_for_tests()
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_path_graph(TENANT))
    monkeypatch.setattr(stores, "_graph_store", store)
    monkeypatch.delenv("AGENT_BOM_MCP_TENANT_ID", raising=False)
    monkeypatch.delenv("AGENT_BOM_TENANT_ID", raising=False)
    keys = auth.KeyStore()
    monkeypatch.setattr(auth, "_key_store", keys)
    token, key = auth.create_api_key(TENANT, auth.Role.VIEWER, tenant_id=TENANT)
    keys.add(key)
    app = FastAPI()
    app.include_router(graph_routes.router, prefix="/v1")
    app.include_router(inventory_assets.router, prefix="/v1")
    app.add_middleware(APIKeyMiddleware, api_key="", allow_unauthenticated=False)
    app.add_middleware(TrustHeadersMiddleware)
    try:
        with TestClient(app, headers={"Authorization": f"Bearer {token}"}) as test_client:
            yield test_client
    finally:
        reset_backpressure_for_tests()


def _call(client, method, path, params, body):
    return client.request(method, path, params=params, json=body)


@pytest.mark.parametrize(("method", "path", "params", "body"), UNPINNED_READS, ids=[f"{m} {p}" for m, p, _, _ in UNPINNED_READS])
def test_unpinned_estate_read_refuses_while_seeding_then_serves(client, seeding, method, path, params, body):
    refused = _call(client, method, path, params, body)
    assert refused.status_code == 503, refused.text
    assert refused.headers["Retry-After"] == "2"
    assert "current_estate_seeding" in refused.text

    seeding._boot_seed_done.set()
    served = _call(client, method, path, params, body)
    assert served.status_code == 200, served.text


def test_reads_pinned_to_a_recorded_scan_still_serve_while_seeding(client, seeding):
    pinned = client.get("/v1/graph/attack-paths", params={"scan_id": "shared-scan"})
    assert pinned.status_code == 200, pinned.text
    assert pinned.json()["pagination"]["total"] == 1


def test_mcp_exposure_paths_refuses_while_seeding(client, seeding, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", TENANT)
    from agent_bom.mcp_server import _execute_tool_async
    from agent_bom.mcp_tools.graph import exposure_paths_impl

    def call() -> dict:
        raw = asyncio.run(_execute_tool_async("exposure_paths", exposure_paths_impl, tenant_id=TENANT, _truncate_response=lambda v: v))
        return json.loads(str(raw))

    refused = call()
    assert refused["error"]["details"]["reason"] == "current_estate_seeding", refused
    assert refused["error"]["details"]["retry_after_seconds"] == 2

    seeding._boot_seed_done.set()
    served = call()
    assert "error" not in served, served
    assert served["paths"], served
