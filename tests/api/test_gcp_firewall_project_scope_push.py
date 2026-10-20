"""Same-named GCP firewall rules in two projects survive push -> SQLite -> current graph as two nodes."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores
from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.push import sanitize_results
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers
from tests.graph.test_gcp_firewall_project_scope import FW_A, FW_B, VM_A, VM_B, _inventories

TENANT = "gcp-fw-tenant"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("agent_bom.api.campaign_reconciliation.poll_campaign_reconciliation", lambda: None)
    original_jobs, original_graph = stores._store, stores._graph_store
    stores.set_job_store(InMemoryJobStore())
    monkeypatch.setattr(stores, "_graph_store", SQLiteGraphStore(str(tmp_path / "graph.db")))
    set_compliance_hub_store(InMemoryComplianceHubStore())
    enable_trusted_proxy_env()
    with TestClient(app) as test_client:
        yield test_client
    stores.set_job_store(original_jobs)
    stores._graph_store = original_graph
    set_compliance_hub_store(None)
    disable_trusted_proxy_env()


def _push(client, source_id: str, inventories: list[dict]) -> None:
    payload = {
        "source_id": source_id,
        "target_scope": "v1:" + (source_id.encode().hex() * 8)[:64],
        "agents": [],
        "cloud_inventory": inventories,
    }
    response = client.post(
        "/v1/results/push",
        json=sanitize_results(payload, source_id=source_id),
        headers=proxy_headers(role="analyst", tenant=TENANT),
    )
    assert response.status_code == 201, response.text


def _current_graph(client) -> dict:
    # /v1/graph answers 409 "restart the query" when another resolve retires the
    # generation mid-read; that is its documented client contract, so restart it
    # (bounded) instead of treating the race as a missing-node failure.
    for _ in range(3):
        response = client.get("/v1/graph", params={"limit": 5000}, headers=proxy_headers(role="viewer", tenant=TENANT))
        if not (response.status_code == 409 and "restart the query" in response.text):
            break
    assert response.status_code == 200, response.text
    return response.json()


def _assert_both_projects_survive(body: dict) -> None:
    nodes = {node["id"]: node for node in body["nodes"]}
    firewalls = {nid for nid in nodes if nid.startswith("cloud_resource:gcp:compute:firewall:")}
    assert firewalls == {FW_A, FW_B}
    assert nodes[FW_A]["attributes"]["account_id"] == "proj-a"
    assert nodes[FW_B]["attributes"]["account_id"] == "proj-b"
    assert nodes[FW_A]["attributes"]["resource_name"] == nodes[FW_B]["attributes"]["resource_name"] == "allow-internal"
    gcp = {nid: node["attributes"].get("account_id") for nid, node in nodes.items() if nid.startswith("cloud_resource:gcp:")}
    by_project = {project: {nid for nid, owner in gcp.items() if owner == project} for project in ("proj-a", "proj-b")}
    assert by_project["proj-a"] == {FW_A, VM_A}
    assert by_project["proj-b"] == {FW_B, VM_B}
    assert not by_project["proj-a"] & by_project["proj-b"]


@pytest.mark.parametrize("reverse", [False, True], ids=["a-then-b", "b-then-a"])
def test_one_push_with_two_projects_keeps_both_firewalls(client, reverse: bool) -> None:
    inventories = _inventories()
    if reverse:
        inventories.reverse()
    _push(client, "gcp-org-scan", inventories)
    _assert_both_projects_survive(_current_graph(client))


@pytest.mark.parametrize("reverse", [False, True], ids=["a-then-b", "b-then-a"])
def test_separate_project_pushes_keep_both_firewalls(client, reverse: bool) -> None:
    inventories = _inventories()
    if reverse:
        inventories.reverse()
    for inventory in inventories:
        _push(client, f"gcp-{inventory['project_id']}", [inventory])
    _assert_both_projects_survive(_current_graph(client))

