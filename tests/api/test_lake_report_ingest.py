"""Lake reports reuse authenticated push, idempotency, graph and finding reads."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.idempotency_store import InMemoryIdempotencyStore
from agent_bom.api.server import app, configure_api
from agent_bom.api.source_store import InMemorySourceStore
from agent_bom.api.store import InMemoryJobStore
from tests.auth_helpers import PROXY_SECRET
from tests.test_lake_evidence_ingest import build


@pytest.fixture
def lake_client(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    configure_api(api_key="test-" + "lake-key")
    monkeypatch.setattr(stores, "_store", InMemoryJobStore())
    monkeypatch.setattr(stores, "_graph_store", SQLiteGraphStore(tmp_path / "lake.db"))
    monkeypatch.setattr(stores, "_idempotency_store", InMemoryIdempotencyStore())
    monkeypatch.setattr(stores, "_source_store", InMemorySourceStore())
    try:
        with TestClient(app) as client:
            yield client
    finally:
        configure_api(api_key=None)


def headers(tenant="lake-tenant"):
    return {"X-Agent-Bom-Role": "analyst", "X-Agent-Bom-Tenant-ID": tenant, "X-Agent-Bom-Proxy-Secret": PROXY_SECRET}


def test_authenticated_lake_push_replay_and_tenant_graph_isolation(lake_client):
    report = build()
    assert lake_client.post("/v1/results/push", json=report).status_code in {401, 403}
    created = lake_client.post("/v1/results/push", json=report, headers=headers())
    assert created.status_code == 201, created.text
    job_id = created.json()["job_id"]
    replay = lake_client.post("/v1/results/push", json=report, headers=headers())
    assert replay.status_code == 201 and replay.json()["job_id"] == job_id
    job = stores._store.get(job_id, tenant_id="lake-tenant")
    assert job.result["findings"][0]["evidence"]["lake_receipt"]["record_id"] == "finding-one"
    assert job.result["graph_persistence"]["status"] == "persisted"
    assert created.json()["graph_persistence"] == job.result["graph_persistence"]
    assert replay.json()["graph_persistence"] == created.json()["graph_persistence"]
    graph = stores._graph_store.load_graph(scan_id=job_id, tenant_id="lake-tenant")
    assert graph.nodes and graph.edges
    assert not stores._graph_store.load_graph(scan_id=job_id, tenant_id="other-tenant").nodes
    other = lake_client.post("/v1/results/push", json=report, headers=headers("other-tenant"))
    assert other.status_code == 201 and other.json()["job_id"] != job_id
    findings = lake_client.get("/v1/findings?window_days=0", headers=headers())
    assert findings.status_code == 200, findings.text
    assert any(row["title"] == "Public bucket" for row in findings.json()["findings"])
