"""Finding disclosure uses the same scope and issue identities as roll-up badges."""

import pytest

from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.rollup_node import node_aggregate, scope_findings
from agent_bom.graph.types import EntityType, RelationshipType

pytestmark = pytest.mark.graph_contract("warn")


def test_shared_scope_findings_are_deduplicated_and_suppressions_match_badges():
    graph = UnifiedGraph(scan_id="scope", tenant_id="one")
    for nid, kind in [
        ("agent", EntityType.AGENT),
        ("other", EntityType.AGENT),
        ("server", EntityType.SERVER),
        ("p1", EntityType.PACKAGE),
        ("p2", EntityType.PACKAGE),
        ("v1", EntityType.VULNERABILITY),
        ("v2", EntityType.VULNERABILITY),
    ]:
        attrs = {"vulnerability_id": "CVE-2025-0001", "finding_id": nid} if nid.startswith("v") else {"ecosystem": "npm", "version": "1"}
        graph.add_node(
            UnifiedNode(id=nid, entity_type=kind, label="same-package" if nid.startswith("p") else nid, attributes=attrs, severity="high")
        )
    for source, target, relation in [
        ("agent", "server", RelationshipType.USES),
        ("other", "server", RelationshipType.USES),
        ("server", "p1", RelationshipType.DEPENDS_ON),
        ("server", "p2", RelationshipType.DEPENDS_ON),
        ("p1", "v1", RelationshipType.VULNERABLE_TO),
        ("p2", "v2", RelationshipType.VULNERABLE_TO),
    ]:
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=relation))
    for suppressed in [frozenset(), frozenset({"v1"}), frozenset({"v1", "v2"})]:
        rows = scope_findings(graph, "agent", suppressed=suppressed)
        aggregate = node_aggregate(graph, "agent", suppressed_finding_ids=suppressed)
        assert aggregate is not None
        assert len(rows) == aggregate.issue_count
        assert len({row["issue_key"] for row in rows}) == len(rows)
    assert len(scope_findings(graph, "agent")) == 1
    assert scope_findings(graph, "agent")[0]["node_ids"] == ["v1", "v2"]
    assert scope_findings(graph, "missing") == []


def test_scope_disclosure_auth_tenants_and_revision_pinning(tmp_path, monkeypatch):
    from uuid import uuid4

    from fastapi.testclient import TestClient

    from agent_bom.api import stores
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.server import app, configure_api
    from agent_bom.api.stores import set_graph_store

    store = SQLiteGraphStore(tmp_path / "scopes.db")
    for tenant in ["alpha", "beta"]:
        graph = UnifiedGraph(scan_id="same-scan", tenant_id=tenant)
        graph.add_node(UnifiedNode(id="same-node", entity_type=EntityType.AGENT, label=f"{tenant} agent"))
        for index in range(3):
            graph.add_node(
                UnifiedNode(
                    id=f"finding-{index}", entity_type=EntityType.MISCONFIGURATION, label=f"{tenant} finding {index}", severity="high"
                )
            )
            graph.add_edge(UnifiedEdge(source="same-node", target=f"finding-{index}", relationship=RelationshipType.CONTAINS))
        store.save_graph(graph)
    original = stores._graph_store
    secret = uuid4().hex
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", secret)
    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    configure_api(api_key=None)
    set_graph_store(store)
    client = TestClient(app)
    params = {"node_id": "same-node", "scan_id": "same-scan", "limit": 1}
    headers = {"X-Agent-Bom-Role": "viewer", "X-Agent-Bom-Tenant-ID": "alpha", "X-Agent-Bom-Proxy-Secret": secret}
    try:
        assert client.get("/v1/graph/scope-findings", params=params).status_code == 401
        for tenant in ["alpha", "beta"]:
            response = client.get("/v1/graph/scope-findings", params=params, headers={**headers, "X-Agent-Bom-Tenant-ID": tenant})
            assert response.status_code == 200
            assert response.json()["findings"][0]["label"] == f"{tenant} finding 0"
            assert response.json()["total"] == 3
        first = client.get("/v1/graph/scope-findings", params=params, headers=headers).json()
        assert client.get("/v1/graph/scope-findings", params={**params, "offset": 1}, headers=headers).status_code == 422
        second = client.get(
            "/v1/graph/scope-findings",
            params={
                **params,
                "offset": 1,
                "snapshot_generation": first["snapshot_generation"],
                "finding_revision": first["finding_revision"],
            },
            headers=headers,
        )
        assert second.status_code == 200
        assert second.json()["total"] == 3
        assert second.json()["findings"][0]["node_ids"] == ["finding-1"]
        assert second.json()["findings"][0]["label"] == "alpha finding 1"
        stale = {**params, "snapshot_generation": first["snapshot_generation"], "finding_revision": "stale"}
        assert client.get("/v1/graph/scope-findings", params=stale, headers=headers).status_code == 409
        assert client.get("/v1/graph/scope-findings", params={**params, "snapshot_generation": "stale"}, headers=headers).status_code == 409
    finally:
        set_graph_store(original)
