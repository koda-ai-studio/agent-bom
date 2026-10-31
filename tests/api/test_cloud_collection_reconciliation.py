"""Native cloud completeness governs durable snapshot reconciliation, not arrivals."""

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores
from agent_bom.api.current_graph import CurrentGraphStore
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.idempotency_store import SQLiteIdempotencyStore
from agent_bom.api.server import app, configure_api
from agent_bom.api.store import SQLiteJobStore
from agent_bom.models import AIBOMReport
from agent_bom.output import to_json
from agent_bom.push import sanitize_results
from tests.auth_helpers import PROXY_SECRET, proxy_headers

BASE_TIME = datetime.now(UTC) - timedelta(hours=2)


def report(provider, account, step, *, empty=False, denied=False, status="ok", suffix=""):
    key = "storage_accounts" if provider == "azure" else "buckets"
    inventory = {
        "provider": provider,
        "account_id": account,
        "status": status,
        key: [] if empty else [{"name": f"{provider}-{account}{suffix}", "tags": {"revision": str(step)}}],
        "warnings": ["Read denied"] if denied else [],
    }
    payload = to_json(AIBOMReport(agents=[], blast_radii=[], cloud_inventory_data=[inventory]))
    payload.update(
        source_id=f"cloud:{provider}:{account}",
        target_scope="v1:" + hashlib.sha256(f"{provider}:{account}".encode()).hexdigest(),
        generated_at=(BASE_TIME + timedelta(minutes=step)).isoformat(),
    )
    return sanitize_results(payload, source_id=payload["source_id"])


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
@pytest.mark.parametrize("partial_status", ["ok", "partial"])
def test_native_partial_full_snapshot_lifecycle_across_accounts_and_tenants(tmp_path, monkeypatch, provider, partial_status):
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "0")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    configure_api(api_key=None)
    monkeypatch.setattr("agent_bom.api.campaign_reconciliation.poll_campaign_reconciliation", lambda: None)
    jobs_path, graph_path = tmp_path / "jobs.db", tmp_path / "graph.db"
    monkeypatch.setattr(stores, "_store", SQLiteJobStore(str(jobs_path)))
    monkeypatch.setattr(stores, "_graph_store", SQLiteGraphStore(str(graph_path)))
    monkeypatch.setattr(stores, "_idempotency_store", SQLiteIdempotencyStore(tmp_path / "idempotency.db"))
    service = {"aws": "s3", "azure": "storage", "gcp": "gcs"}[provider]
    asset = f"cloud_resource:{provider}:{service}:bucket:{provider}-account-a"
    peer = f"cloud_resource:{provider}:{service}:bucket:{provider}-account-b"
    with TestClient(app) as client:

        def push(payload, tenant="cloud-a"):
            response = client.post("/v1/results/push", json=payload, headers=proxy_headers("analyst", tenant))
            assert response.status_code == 201
            return response.json()

        def current(tenant="cloud-a"):
            reader = CurrentGraphStore(stores._graph_store, stores._store)
            return reader.load_graph(tenant_id=tenant)

        initial = report(provider, "account-a", 0)
        first = push(initial)
        push(report(provider, "account-b", 0))
        push(initial, tenant="cloud-b")
        nodes = set(current().nodes)
        assert asset in nodes and peer in nodes
        assert push(initial)["job_id"] == first["job_id"]
        assert set(current().nodes) == nodes
        push(report(provider, "account-a", 1))
        assert set(current().nodes) == nodes
        assert current().nodes[asset].attributes["tags"]["revision"] == "1"
        partial = report(provider, "account-a", 2, denied=partial_status == "ok", status=partial_status, suffix="-new")
        assert partial["scan_run"]["outcome"] == "partial"
        assert push(partial)["scan_outcome"] == "partial"
        assert asset in current().nodes and peer in current().nodes
        added = asset + "-new"
        assert current().nodes[added].attributes["tags"]["revision"] == "2"
        assert current().nodes[asset].attributes["tags"]["revision"] == "1"
        assert added not in current("cloud-b").nodes
        monkeypatch.setattr(stores, "_store", SQLiteJobStore(str(jobs_path)))
        monkeypatch.setattr(stores, "_graph_store", SQLiteGraphStore(str(graph_path)))
        assert added in current().nodes and asset in current().nodes
        push(report(provider, "account-a", 3, empty=True))
        deleted = current()
        assert asset not in deleted.nodes and added not in deleted.nodes and peer in deleted.nodes
        assert all(asset not in (edge.source, edge.target) for edge in deleted.edges)
        push(report(provider, "account-a", 1))
        assert asset not in current().nodes
        push(report(provider, "account-a", 4))
        assert set(current().nodes) == nodes
        assert current().nodes[asset].attributes["tags"]["revision"] == "4"
        assert current("cloud-b").nodes[asset].attributes["tags"]["revision"] == "0"
        monkeypatch.setattr(stores, "_store", SQLiteJobStore(str(jobs_path)))
        monkeypatch.setattr(stores, "_graph_store", SQLiteGraphStore(str(graph_path)))
        assert set(current().nodes) == nodes
        assert current().nodes[asset].attributes["tags"]["revision"] == "4"
        assert not current("unrelated").nodes
        assert client.get("/v1/graph").status_code == 401
