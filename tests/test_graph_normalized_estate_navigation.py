"""Recorded account identity and findings survive normalized estate navigation.

Synthetic raw inventory deliberately repeats instance IDs and names across six
accounts in two organizations. No graph edges are constructed by this fixture.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent_bom.api import auth, stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.middleware import APIKeyMiddleware, TrustHeadersMiddleware
from agent_bom.api.routes import graph as routes
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph


def _report(org: int, resources: int) -> dict:
    accounts = [str(123456789012 + org * 10 + index) for index in range(3)]
    inventories, findings = [], []
    for account in accounts:
        instances = []
        for index in range(resources):
            arn = f"arn:aws:ec2:us-east-1:{account}:instance/i-{index:08x}"
            instances.append({"instance_id": f"i-{index:08x}", "arn": arn, "name": f"payments-{index}"})
            if index % 10 == 0:
                findings.append(
                    {
                        "id": f"f-{account}-{index}",
                        "source": "CLOUD_CIS",
                        "finding_type": "CIS_FAIL",
                        "title": "Instance configuration needs review",
                        "severity": "high",
                        "account_ref": account,
                        "asset": {"name": f"payments-{index}", "identifier": arn, "asset_type": "cloud_resource", "provider": "aws"},
                    }
                )
        inventories.append({"provider": "aws", "status": "ok", "account_id": account, "region": "us-east-1", "instances": instances})
    return {
        "scan_sources": ["cloud-inventory"],
        "aws_organization": {
            "status": "ok",
            "org_id": f"o-synthetic{org}",
            "accounts": [{"id": account, "name": "Payments", "status": "ACTIVE"} for account in accounts],
        },
        "cloud_inventory": inventories,
        "findings": findings,
    }


def normalized_estate(resources: int, tenant: str) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="normalized-estate", tenant_id=tenant)
    for org in range(2):
        build_unified_graph_from_report(_report(org, resources), scan_id=graph.scan_id, tenant_id=tenant, container=graph)
    return graph


@pytest.mark.parametrize("resources", [20, 200])
def test_normalized_estate_reconciles_across_authenticated_rollup_drilldown_and_restart(tmp_path, monkeypatch, resources):
    store = SQLiteGraphStore(tmp_path / "estate.db")
    graph = normalized_estate(resources, "estate-a")
    instances = [node for node in graph.nodes.values() if node.attributes.get("resource_kind") == "ec2-instance"]
    assert len(instances) == resources * 6
    assert len({node.id for node in instances}) == resources * 6
    assert len({node.attributes["account_id"] for node in instances}) == 6
    # A configuration finding does not establish Internet exposure.
    assert not any(node.attributes.get("internet_exposed") is True for node in instances)
    assert all(edge.source in graph.nodes and edge.target in graph.nodes for edge in graph.edges)
    store.save_graph(graph)
    other = normalized_estate(10, "estate-b")
    store.save_graph(other)  # Same snapshot and asset keys, different tenant.
    monkeypatch.setattr(stores, "_graph_store", SQLiteGraphStore(tmp_path / "estate.db"))
    keys = auth.KeyStore()
    monkeypatch.setattr(auth, "_key_store", keys)
    token, key = auth.create_api_key("estate-viewer", auth.Role.VIEWER, tenant_id="estate-a")
    keys.add(key)
    app = FastAPI()
    app.include_router(routes.router, prefix="/v1")
    app.add_middleware(APIKeyMiddleware, api_key="", allow_unauthenticated=False)
    app.add_middleware(TrustHeadersMiddleware)
    with TestClient(app) as client:
        assert client.get("/v1/graph/rollup").status_code == 401

        def get(path, **params):
            response = client.get(
                path,
                params={"scan_id": graph.scan_id, "tenant_id": "estate-b", **params},
                headers={"Authorization": f"Bearer {token}", "X-Agent-Bom-Tenant-ID": "estate-b"},
            )
            assert response.status_code == 200, response.text[:200]
            return response.json()

        overview = get("/v1/graph/rollup")
        assert overview["tenant_id"] == "estate-a"
        assert overview["summary"]["issue_count"] == resources * 6 // 10
        assert overview["summary"]["finding_occurrence_count"] == resources * 6 // 10
        for org in range(2):
            root = next(item for item in overview["top_level"] if item["id"] == f"org:aws:o-synthetic{org}")
            assert root["aggregate"]["issue_count"] == resources * 3 // 10
            accounts = get("/v1/graph/rollup", node=root["id"])["children"]
            assert {item["id"] for item in accounts} == {f"account:aws:{123456789012 + org * 10 + i}" for i in range(3)}
            for account in accounts:
                assert account["aggregate"]["issue_count"] == resources // 10
                page = get("/v1/graph/rollup", node=account["id"], limit=7)
                assert len(page["children"]) == 7
                assert page["pagination"]["has_more"] is True
                seen = set()
                while True:
                    ids = {item["id"] for item in page["children"]}
                    assert not ids & seen
                    seen.update(ids)
                    if not page["pagination"]["has_more"]:
                        break
                    page = get(
                        "/v1/graph/rollup",
                        node=account["id"],
                        limit=7,
                        offset=len(seen),
                        snapshot_generation=page["snapshot_generation"],
                    )
                expected = {node.id for node in instances if node.attributes["account_id"] == account["id"].split(":")[-1]}
                assert seen == expected
                child = get("/v1/graph/rollup", node=sorted(expected)[0])
                assert child["node"]["id"] in expected
                assert len(child["children"]) == 1
                assert child["children"][0]["entity_type"] == "misconfiguration"
                aggregate = get("/v1/graph/node-aggregates", node_id=child["node"]["id"])
                assert aggregate["aggregates"][0]["aggregate"]["issue_count"] == 1
        assert get("/v1/graph/rollup")["summary"] == overview["summary"]
