"""The default node page embeds a bounded, ranked slice of its attack paths and says so.

A correlated estate gives every agent on the first page several recorded
paths, each carrying its full exposure record. Embedding all of them made the
first page grow with the path count instead of the page size; the complete
ranked set stays on ``/v1/graph/attack-paths``.
"""

from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.routes.graph_routes.params import _NODE_PAGE_ATTACK_PATH_LIMIT
from agent_bom.api.server import app
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _graph(paths: int) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="paths-scan", tenant_id="default")
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a", severity="critical", risk_score=9.9))
    for index in range(paths):
        vuln = f"vuln:CVE-{index}"
        graph.add_node(UnifiedNode(id=vuln, entity_type=EntityType.VULNERABILITY, label=f"CVE-{index}", severity="low"))
        graph.add_edge(UnifiedEdge(source="agent:a", target=vuln, relationship=RelationshipType.VULNERABLE_TO))
        graph.attack_paths.append(
            AttackPath(
                source="agent:a",
                target=vuln,
                hops=["agent:a", vuln],
                edges=["vulnerable_to"],
                composite_risk=90.0 - index * 0.01,
                summary=f"path {index}",
                vuln_ids=[f"CVE-{index}"],
            )
        )
    return graph


def _page(tmp_path, paths: int) -> dict:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_graph(paths))
    original = api_stores._graph_store
    api_stores.set_graph_store(store)
    try:
        response = TestClient(app).get("/v1/graph", params={"scan_id": "paths-scan", "limit": 5})
    finally:
        api_stores.set_graph_store(original)
    assert response.status_code == 200, response.text
    return response.json()


def test_first_page_embeds_at_most_the_page_path_limit(tmp_path) -> None:
    body = _page(tmp_path, _NODE_PAGE_ATTACK_PATH_LIMIT + 15)
    assert len(body["attack_paths"]) == _NODE_PAGE_ATTACK_PATH_LIMIT
    assert body["attack_path_pagination"] == {
        "total": _NODE_PAGE_ATTACK_PATH_LIMIT + 15,
        "limit": _NODE_PAGE_ATTACK_PATH_LIMIT,
        "has_more": True,
        "endpoint": "/v1/graph/attack-paths",
    }
    risks = [path["composite_risk"] for path in body["attack_paths"]]
    assert risks == sorted(risks, reverse=True), "the embedded slice must be the highest-ranked paths"


def test_small_path_set_is_embedded_whole(tmp_path) -> None:
    body = _page(tmp_path, 3)
    assert len(body["attack_paths"]) == 3
    assert body["attack_path_pagination"]["has_more"] is False
