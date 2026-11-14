"""``GET /v1/graph?view=summary``: the opt-in lean projection; the default stays ``full`` in 0.115.

The summary carries each node's identity, kind, label, severity, risk and
status plus the few attributes that name and badge it, each edge's endpoints
and relationship, and a compact summary of each embedded attack path. Full
attributes and provenance come from ``/v1/graph/node/{id}``, full paths from
``/v1/graph/attack-paths``. ``summary`` becomes the default in 0.116.0.
"""

from __future__ import annotations

import pathlib
import re

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.routes.graph_routes.lean_view import (
    LEAN_ATTACK_PATH_FIELDS,
    LEAN_EDGE_FIELDS,
    LEAN_NODE_ATTRIBUTES,
    LEAN_NODE_FIELDS,
)
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from tests.test_graph_api import _RecordingGraphStore

UI = pathlib.Path(__file__).resolve().parents[2] / "ui"


@pytest.fixture
def recording_graph_store(monkeypatch):
    from agent_bom.cloud import runtime_workload_evidence_store as runtime_evidence

    monkeypatch.setattr(runtime_evidence, "_default_store", None)
    original = api_stores._graph_store
    store = _RecordingGraphStore()
    set_graph_store(store)
    try:
        yield store
    finally:
        set_graph_store(original)


@pytest.fixture(scope="module")
def showcase_graph() -> UnifiedGraph:
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_SCAN_ID, SHOWCASE_TENANT, seed_showcase_graph_if_empty
    from tests.test_demo_graph_data_model import _CapturingStore

    store = _CapturingStore()
    seed_showcase_graph_if_empty(store, tenant_id=SHOWCASE_TENANT)
    graph = next(graph for graph in store.graphs if graph.scan_id == SHOWCASE_SCAN_ID)
    graph.tenant_id = "default"
    return graph


def _small_graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="store-scan", tenant_id="default")
    graph.add_node(
        UnifiedNode(
            id="agent:a",
            entity_type=EntityType.AGENT,
            label="agent-a",
            severity="high",
            risk_score=7.5,
            attributes={"agent_type": "claude-desktop", "configuration": {"bulky": "x" * 400}, "tags": {"team": "a"}},
        )
    )
    graph.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="server-s", attributes={"transport": "stdio"}))
    graph.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1", severity="critical", risk_score=9.0))
    graph.add_edge(UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES, evidence={"source": "scan"}))
    graph.add_edge(UnifiedEdge(source="server:s", target="vuln:CVE-1", relationship=RelationshipType.VULNERABLE_TO, evidence={"x": 1}))
    graph.attack_paths.append(
        AttackPath(
            source="agent:a",
            target="vuln:CVE-1",
            hops=["agent:a", "server:s", "vuln:CVE-1"],
            edges=["uses", "vulnerable_to"],
            composite_risk=9.0,
            summary="agent-a reaches CVE-1",
            vuln_ids=["CVE-1"],
        )
    )
    return graph


def _get(client: TestClient, **params):
    response = client.get("/v1/graph", params={"scan": "store-scan", **params})
    assert response.status_code == 200, response.text[:400]
    return response


@pytest.mark.parametrize("extra", [{"limit": 50}, {"relationships": "uses,vulnerable_to"}], ids=["node-page", "investigation-load"])
def test_summary_view_is_the_lean_projection(recording_graph_store, extra) -> None:
    recording_graph_store.graph = _small_graph()
    body = _get(TestClient(app), view="summary", **extra).json()

    assert body["view"] == "summary"
    assert body["nodes"] and body["edges"]
    for node in body["nodes"]:
        assert set(node) <= {*LEAN_NODE_FIELDS, "context"}, sorted(set(node) - set(LEAN_NODE_FIELDS))
        assert set(node.get("attributes") or {}) <= set(LEAN_NODE_ATTRIBUTES)
        assert "evidence_provenance" not in node
    agent = next(node for node in body["nodes"] if node["id"] == "agent:a")
    assert agent == {
        "id": "agent:a",
        "entity_type": "agent",
        "label": "agent-a",
        "severity": "high",
        "risk_score": 7.5,
        "status": agent["status"],
        "attributes": {"agent_type": "claude-desktop"},
    }
    for edge in body["edges"]:
        assert set(edge) <= set(LEAN_EDGE_FIELDS)
        assert {"source", "target", "relationship", "direction"} <= set(edge)
    for path in body.get("attack_paths") or []:
        assert set(path) <= set(LEAN_ATTACK_PATH_FIELDS)


def test_a_lean_edge_names_its_full_record_by_relationship_source_target(recording_graph_store) -> None:
    recording_graph_store.graph = _small_graph()
    client = TestClient(app)
    full = {edge["id"]: edge for edge in _get(client, view="full", limit=50).json()["edges"]}
    lean = _get(client, view="summary", limit=50).json()["edges"]
    assert lean and len(lean) == len(full)
    for edge in lean:
        whole = full[f"{edge['relationship']}:{edge['source']}:{edge['target']}"]
        assert edge == {key: whole[key] for key in LEAN_EDGE_FIELDS}


def test_lean_is_an_alias_of_summary(recording_graph_store) -> None:
    recording_graph_store.graph = _small_graph()
    client = TestClient(app)
    assert _get(client, view="lean").content == _get(client, view="summary").content


@pytest.mark.parametrize("extra", [{"limit": 50}, {"relationships": "uses,vulnerable_to"}], ids=["node-page", "investigation-load"])
def test_default_stays_the_full_response_in_this_release(recording_graph_store, extra) -> None:
    """External clients read node attributes from the default response; summary becomes the default in 0.116."""
    recording_graph_store.graph = _small_graph()
    client = TestClient(app)
    default = _get(client, **extra)
    assert default.content == _get(client, view="full", **extra).content
    body = default.json()
    assert "view" not in body
    agent = next(node for node in body["nodes"] if node["id"] == "agent:a")
    assert agent["attributes"]["configuration"] == {"bulky": "x" * 400} and "evidence_provenance" in agent


@pytest.mark.parametrize("extra", [{"limit": 50}, {"relationships": "uses,vulnerable_to"}], ids=["node-page", "investigation-load"])
def test_full_and_include_both_return_the_previous_default(recording_graph_store, extra) -> None:
    recording_graph_store.graph = _small_graph()
    client = TestClient(app)

    full = _get(client, view="full", **extra)
    included = _get(client, include="attributes,paths", **extra)
    reordered = _get(client, include="paths,attributes", **extra)

    assert full.content == included.content == reordered.content
    body = full.json()
    assert "view" not in body
    graph = recording_graph_store.graph
    assert {node["id"]: {k: v for k, v in node.items() if k != "context"} for node in body["nodes"]} == {
        node_id: node.to_dict() for node_id, node in graph.nodes.items() if node_id in {n["id"] for n in body["nodes"]}
    }
    assert all("evidence_provenance" in node and "source_id" in edge for node, edge in zip(body["nodes"], body["edges"]))


def test_include_attributes_alone_restores_node_and_edge_records_only(recording_graph_store) -> None:
    recording_graph_store.graph = _small_graph()
    client = TestClient(app)
    full = _get(client, view="full", limit=50).json()
    body = _get(client, include="attributes", limit=50).json()
    assert body["view"] == "summary"
    assert body["nodes"] == full["nodes"] and body["edges"] == full["edges"]
    assert all(set(path) <= set(LEAN_ATTACK_PATH_FIELDS) for path in body["attack_paths"])

    paths_only = _get(client, include="paths", limit=50).json()
    assert paths_only["attack_paths"] == full["attack_paths"]
    assert all("evidence_provenance" not in node for node in paths_only["nodes"])


@pytest.mark.parametrize("params", [{"include": "attributes,secrets"}, {"view": "slim"}, {"view": "canvas", "include": "paths"}])
def test_unknown_or_conflicting_projection_is_rejected(recording_graph_store, params) -> None:
    recording_graph_store.graph = _small_graph()
    response = TestClient(app).get("/v1/graph", params={"scan": "store-scan", **params})
    assert response.status_code == 422, response.text[:300]


def test_lean_paths_keep_identity_to_join_the_full_path(recording_graph_store) -> None:
    recording_graph_store.graph = _small_graph()
    client = TestClient(app)
    lean = _get(client, view="summary", limit=50).json()["attack_paths"]
    full = _get(client, view="full", limit=50).json()["attack_paths"]
    assert lean and len(lean) == len(full)
    for slim, whole in zip(lean, full):
        assert slim == {key: whole[key] for key in LEAN_ATTACK_PATH_FIELDS if key in whole}


def test_node_detail_still_returns_full_attributes_and_provenance(recording_graph_store) -> None:
    recording_graph_store.graph = _small_graph()
    client = TestClient(app)
    lean_node = next(n for n in _get(client, view="summary", limit=50).json()["nodes"] if n["id"] == "agent:a")
    assert "configuration" not in lean_node["attributes"]

    detail = client.get("/v1/graph/node/agent:a", params={"scan_id": "store-scan"})
    assert detail.status_code == 200, detail.text[:300]
    node = detail.json()["node"]
    assert node["attributes"]["configuration"] == {"bulky": "x" * 400}
    assert node["attributes"]["tags"] == {"team": "a"}
    assert node["evidence_provenance"]["schema_version"] == "agent-bom.graph-evidence/v1"


def test_summary_view_is_at_least_five_times_smaller_on_the_showcase_estate(recording_graph_store, showcase_graph) -> None:
    recording_graph_store.graph = showcase_graph
    client = TestClient(app)
    params = {"scan": showcase_graph.scan_id, "limit": 500}

    lean = client.get("/v1/graph", params={**params, "view": "summary"})
    full = client.get("/v1/graph", params=params)

    assert lean.status_code == full.status_code == 200
    nodes = len(lean.json()["nodes"])
    assert nodes == len(full.json()["nodes"]) and nodes >= 500
    assert len(full.content) >= 5 * len(lean.content), (len(full.content), len(lean.content))
    assert len(lean.content) / nodes < 800, len(lean.content) / nodes


def test_every_ui_graph_load_names_its_projection() -> None:
    """The default changes to summary in 0.116; a UI caller that renders more must name its projection."""
    calls = []
    for module in [*UI.glob("lib/**/*.ts"), *UI.glob("hooks/**/*.ts*"), *UI.glob("components/**/*.tsx"), *UI.glob("app/**/*.tsx")]:
        if re.search(r"\.(test|spec)\.", module.name):
            continue
        text = module.read_text(encoding="utf-8")
        for match in re.finditer(r"\bapi\s*\.getGraph\(\{", text):
            body = text[match.end() : text.find("})", match.end())]
            calls.append((module.relative_to(UI).as_posix(), re.search(r"\bview:\s*\"(canvas|full)\"", body) is not None))
    assert calls, "no getGraph caller found"
    assert [module for module, named in calls if not named] == []
