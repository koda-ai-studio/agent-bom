"""Documented 200 contracts for the graph read endpoints.

Every JSON GET under ``/v1/graph`` names a response model in OpenAPI, and the
live body from a small persisted graph validates against it with no top-level
key left undocumented.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.read_models import STRICT_CONTRACT
from agent_bom.api.read_models import graph as graph_models
from agent_bom.api.read_models.exploit_story import GraphExploitStoryResponse
from agent_bom.api.read_models.graph_vendor_paths import GraphCrossVendorPathsResponse
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode

GRAPH_TYPED_READS: dict[str, type[BaseModel]] = {
    "/v1/graph": graph_models.GraphPageResponse,
    "/v1/graph/agents": graph_models.GraphAgentsResponse,
    "/v1/graph/attack-paths/cross-vendor": GraphCrossVendorPathsResponse,
    "/v1/graph/changes": graph_models.GraphEstateChangesResponse,
    "/v1/graph/clusters": graph_models.GraphClustersResponse,
    "/v1/graph/compliance": graph_models.GraphComplianceResponse,
    "/v1/graph/diff": graph_models.GraphDiffResponse,
    "/v1/graph/edges/active": graph_models.GraphActiveEdgesResponse,
    "/v1/graph/edges/changes": graph_models.GraphEdgeChangesResponse,
    "/v1/graph/evidence-manifest": graph_models.GraphEvidenceManifestResponse,
    "/v1/graph/exploit-story": GraphExploitStoryResponse,
    "/v1/graph/exposure-paths": graph_models.GraphExposurePathsResponse,
    "/v1/graph/governance": graph_models.GraphGovernanceResponse,
    "/v1/graph/history": graph_models.GraphHistoryResponse,
    "/v1/graph/impact": graph_models.GraphImpactResponse,
    "/v1/graph/legend": graph_models.GraphLegendResponse,
    "/v1/graph/nhi/governance": graph_models.GraphNhiGovernanceResponse,
    "/v1/graph/node-context": graph_models.GraphNodeContextResponse,
    "/v1/graph/node/{node_id}": graph_models.GraphNodeContextResponse,
    "/v1/graph/node-neighbors": graph_models.GraphNodeNeighborsResponse,
    "/v1/graph/node/{node_id}/neighbors": graph_models.GraphNodeNeighborsResponse,
    "/v1/graph/paths": graph_models.GraphPathsResponse,
    "/v1/graph/presets": graph_models.GraphPresetsResponse,
    "/v1/graph/rollup": graph_models.GraphRollupResponse,
    "/v1/graph/schema": graph_models.GraphSchemaResponse,
    "/v1/graph/search": graph_models.GraphSearchResponse,
    "/v1/graph/snapshots": graph_models.GraphSnapshotsResponse,
}

# GETs that already carried a 200 schema before the read-model pass: an inline
# OpenAPI contract (fix-first, attack-paths) or a validated Pydantic model.
PREVIOUSLY_DOCUMENTED = {
    "/v1/graph/views/fix-first",
    "/v1/graph/attack-paths",
    "/v1/graph/scoped",
    "/v1/graph/incident-edges",
    "/v1/graph/scenarios",
    "/v1/graph/correlations",
}


def _openapi_paths() -> dict[str, Any]:
    app.openapi_schema = None
    return app.openapi()["paths"]


def test_every_graph_json_get_documents_a_200_model() -> None:
    paths = _openapi_paths()
    graph_gets = {path for path, ops in paths.items() if path.startswith("/v1/graph") and "get" in ops}
    for path in sorted(graph_gets - PREVIOUSLY_DOCUMENTED):
        schema = paths[path]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
        model = GRAPH_TYPED_READS.get(path)
        if model is None and path.startswith(("/v1/graph/scenarios", "/v1/graph/correlations", "/v1/graph/compromise")):
            continue
        assert model is not None, f"{path} has no documented graph read model"
        assert schema == {"$ref": f"#/components/schemas/{model.__name__}"}, path


def _persist(store: SQLiteGraphStore, scan_id: str, *, extra_vuln: bool) -> None:
    graph = UnifiedGraph(scan_id=scan_id)
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
    graph.add_node(UnifiedNode(id="server:a:fs", entity_type=EntityType.SERVER, label="mcp-fs"))
    graph.add_node(UnifiedNode(id="pkg:npm:x", entity_type=EntityType.PACKAGE, label="x"))
    graph.add_node(UnifiedNode(id="identity:a", entity_type=EntityType.MANAGED_IDENTITY, label="identity-a"))
    graph.add_edge(UnifiedEdge(source="agent:a", target="server:a:fs", relationship=RelationshipType.USES))
    graph.add_edge(UnifiedEdge(source="server:a:fs", target="pkg:npm:x", relationship=RelationshipType.DEPENDS_ON))
    if extra_vuln:
        graph.add_node(
            UnifiedNode(id="vuln:CVE-2024-1", entity_type=EntityType.VULNERABILITY, label="CVE-2024-1", severity="critical", risk_score=9.0)
        )
        graph.add_edge(UnifiedEdge(source="pkg:npm:x", target="vuln:CVE-2024-1", relationship=RelationshipType.VULNERABLE_TO))
        graph.attack_paths.append(
            AttackPath(
                source="agent:a",
                target="vuln:CVE-2024-1",
                hops=["agent:a", "server:a:fs", "pkg:npm:x", "vuln:CVE-2024-1"],
                edges=["uses", "depends_on", "vulnerable_to"],
                composite_risk=9.0,
                summary="agent-a -> CVE-2024-1",
                vuln_ids=["CVE-2024-1"],
            )
        )
    store.save_graph(graph)


@pytest.fixture()
def graph_client(tmp_path: Any, monkeypatch: pytest.MonkeyPatch):
    from agent_bom.api.store import InMemoryJobStore
    from agent_bom.backpressure import reset_backpressure_for_tests

    reset_backpressure_for_tests()
    monkeypatch.setattr(api_stores, "_store", InMemoryJobStore())
    store = SQLiteGraphStore(tmp_path / "contract-graph.db")
    _persist(store, "contract-s1", extra_vuln=False)
    _persist(store, "contract-s2", extra_vuln=True)
    original = api_stores._graph_store
    set_graph_store(store)
    try:
        yield TestClient(app)
    finally:
        api_stores._graph_store = original
        reset_backpressure_for_tests()


LIVE_REQUESTS: dict[str, str] = {
    "/v1/graph": "/v1/graph",
    "/v1/graph/agents": "/v1/graph/agents",
    "/v1/graph/changes": "/v1/graph/changes",
    "/v1/graph/clusters": "/v1/graph/clusters",
    "/v1/graph/compliance": "/v1/graph/compliance",
    "/v1/graph/diff": "/v1/graph/diff?old=contract-s1&new=contract-s2",
    "/v1/graph/edges/active": "/v1/graph/edges/active?at=2999-01-01T00:00:00Z",
    "/v1/graph/edges/changes": "/v1/graph/edges/changes?old=contract-s1&new=contract-s2",
    "/v1/graph/evidence-manifest": "/v1/graph/evidence-manifest",
    "/v1/graph/exploit-story": "/v1/graph/exploit-story?node=vuln:CVE-2024-1&package=pkg:npm:x",
    "/v1/graph/exposure-paths": "/v1/graph/exposure-paths",
    "/v1/graph/governance": "/v1/graph/governance",
    "/v1/graph/history": "/v1/graph/history",
    "/v1/graph/impact": "/v1/graph/impact?node=pkg:npm:x",
    "/v1/graph/legend": "/v1/graph/legend",
    "/v1/graph/nhi/governance": "/v1/graph/nhi/governance",
    "/v1/graph/node-context": "/v1/graph/node-context?node_id=server:a:fs",
    "/v1/graph/node-neighbors": "/v1/graph/node-neighbors?node_id=server:a:fs",
    "/v1/graph/paths": "/v1/graph/paths?source_id=agent:a",
    "/v1/graph/presets": "/v1/graph/presets",
    "/v1/graph/rollup": "/v1/graph/rollup",
    "/v1/graph/schema": "/v1/graph/schema",
    "/v1/graph/search": "/v1/graph/search?q=agent",
    "/v1/graph/snapshots": "/v1/graph/snapshots",
}


def _top_level_undeclared(model: type[BaseModel], body: Any) -> list[str]:
    if not isinstance(body, dict):
        return []
    return sorted(set(body) - set(model.model_fields))


@pytest.mark.parametrize("path", sorted(LIVE_REQUESTS))
def test_live_graph_body_matches_documented_model(graph_client: TestClient, path: str) -> None:
    response = graph_client.get(LIVE_REQUESTS[path])
    assert response.status_code == 200, response.text[:300]
    body = response.json()
    model = GRAPH_TYPED_READS[path]
    model.model_validate(body, context={STRICT_CONTRACT: True})
    assert _top_level_undeclared(model, body) == []


def test_missing_node_neighbors_body_matches_documented_model(graph_client: TestClient) -> None:
    body = graph_client.get("/v1/graph/node-neighbors?node_id=missing:node").json()
    assert body["found"] is False
    graph_models.GraphNodeNeighborsResponse.model_validate(body, context={STRICT_CONTRACT: True})
    assert _top_level_undeclared(graph_models.GraphNodeNeighborsResponse, body) == []


@pytest.mark.parametrize(
    ("collection", "field", "bad_value"),
    [
        ("nodes", "id", None),
        ("nodes", "risk_score", "not-a-score"),
        ("edges", "target", None),
        ("edges", "confidence", "not-a-confidence"),
        ("attack_paths", "hops", "not-a-list"),
        ("attack_paths", "composite_risk", "not-a-score"),
    ],
)
def test_nested_graph_contract_detects_invalid_wire_fields(graph_client, collection, field, bad_value):
    from pydantic import ValidationError

    body = graph_client.get("/v1/graph?scan_id=contract-s2").json()
    assert body[collection], collection
    body[collection][0][field] = bad_value
    with pytest.raises(ValidationError):
        graph_models.GraphPageResponse.model_validate(body, context={STRICT_CONTRACT: True})


def test_graph_openapi_reuses_nested_wire_contracts():
    app.openapi_schema = None
    schemas = app.openapi()["components"]["schemas"]
    expected = {"nodes": "GraphNodeRecord", "edges": "GraphEdgeRecord", "attack_paths": "GraphAttackPathRecord"}
    for field, name in expected.items():
        assert schemas["GraphPageResponse"]["properties"][field]["items"] == {"$ref": f"#/components/schemas/{name}"}
    assert schemas["GraphNodeNeighborsResponse"]["properties"]["neighbors"]["items"] == {"$ref": "#/components/schemas/GraphNodeRecord"}
    assert schemas["GraphClustersResponse"]["properties"]["clusters"]["items"] == {"$ref": "#/components/schemas/SemanticCluster"}
    assert schemas["GraphAttackPathRecord"]["properties"]["technique_mappings"]["items"] == {
        "$ref": "#/components/schemas/TechniqueMapping"
    }


def test_graph_wire_contract_preserves_provider_fields_and_unknown_extensions(graph_client):
    body = graph_client.get("/v1/graph?scan_id=contract-s2").json()
    body["nodes"][0]["attributes"]["provider_extension"] = {"nested": [True, None, 1, "value"]}
    body["nodes"][0]["future_additive_field"] = {"state": "recorded"}
    body["edges"][0]["evidence"]["provider_extension"] = ["recorded", {"count": 1}]
    parsed = graph_models.GraphPageResponse.model_validate(body, context={STRICT_CONTRACT: True})
    assert parsed.model_dump(mode="json", exclude_unset=True) == body


@pytest.mark.parametrize(
    ("url", "model", "collection"),
    [
        ("/v1/graph?scan_id=contract-s2", graph_models.GraphPageResponse, "nodes"),
        ("/v1/graph?scan_id=contract-s2", graph_models.GraphPageResponse, "edges"),
        ("/v1/graph?scan_id=contract-s2", graph_models.GraphPageResponse, "attack_paths"),
        ("/v1/graph/agents?scan_id=contract-s2", graph_models.GraphAgentsResponse, "agents"),
        ("/v1/graph/governance?scan_id=contract-s2", graph_models.GraphGovernanceResponse, "nodes"),
        ("/v1/graph/exposure-paths?scan_id=contract-s2", graph_models.GraphExposurePathsResponse, "nodes"),
        ("/v1/graph/rollup?scan_id=contract-s2&mode=attack_path", graph_models.GraphRollupResponse, "path_nodes"),
        ("/v1/graph/rollup?scan_id=contract-s2&mode=attack_path", graph_models.GraphRollupResponse, "path_edges"),
        ("/v1/graph/rollup?scan_id=contract-s2&mode=attack_path", graph_models.GraphRollupResponse, "attack_paths"),
        ("/v1/graph/clusters?scan_id=contract-s2&min_members=1", graph_models.GraphClustersResponse, "clusters"),
        ("/v1/graph/search?q=agent&scan_id=contract-s2", graph_models.GraphSearchResponse, "results"),
        (
            "/v1/graph/node-neighbors?node_id=server:a:fs&scan_id=contract-s2",
            graph_models.GraphNodeNeighborsResponse,
            "neighbors",
        ),
    ],
)
def test_nonempty_graph_records_round_trip_without_undeclared_fields(graph_client, url, model, collection):
    response = graph_client.get(url)
    assert response.status_code == 200
    body = response.json()
    assert body[collection], collection
    parsed = model.model_validate(body, context={STRICT_CONTRACT: True})
    assert parsed.model_dump(mode="json", exclude_unset=True) == body
    for record in getattr(parsed, collection):
        if isinstance(record, BaseModel):
            assert not record.model_extra, record.model_extra


def test_technique_mapping_wire_contract_uses_existing_serializer():
    from agent_bom.api.read_models.graph_records import GraphAttackPathRecord
    from agent_bom.graph.technique_mapping import TechniqueMapping

    path = AttackPath(
        source="agent:a",
        target="pkg:npm:x",
        technique_mappings=[TechniqueMapping(0, "T1078", evidence_basis="observed", confidence=0.8)],
    ).to_dict()
    parsed = GraphAttackPathRecord.model_validate(path)
    assert parsed.model_dump(mode="json", exclude_unset=True) == path
    assert not parsed.model_extra


def test_documented_graph_contract_keeps_runtime_response_serialization():
    from fastapi import FastAPI

    from agent_bom.api.read_models._base import documented

    # Existing documentation-only behavior: drift is caught by contract tests,
    # not by filtering/rejecting a handler's response during a user request.
    probe = FastAPI()
    body = {"nodes": [{"id": None, "future_field": "retained"}]}

    @probe.get("/graph", **documented(graph_models.GraphPageResponse))
    def read():
        return body

    response = TestClient(probe).get("/graph")
    assert response.status_code == 200
    assert response.json() == body
