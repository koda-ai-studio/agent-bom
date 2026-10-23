"""`GET /v1/graph` must carry the agent stack above the findings it ranks.

Measured on the demo estate (6,853 nodes): the default page returned 895 nodes
including 172 CVEs, but 0 packages, 0 servers and 0 agents. Every CVE arrived
without the package it lives in, the workload that depends on that package or
the agent that uses the workload, because the page's context walk followed
containment edges (contains/hosts/owns) only. A CVE on its own answers nothing.
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi.testclient import TestClient

from agent_bom.api.graph_page_stack import STACK_FANOUT, page_agent_stack
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedNode
from tests._demo_estate_fixtures import VIEWER


class _FakeStore:
    def __init__(self, nodes: list[UnifiedNode], edges: list[UnifiedEdge]) -> None:
        self.nodes = {node.id: node for node in nodes}
        self.edges = edges

    def edges_for_node_ids(self, *, node_ids: set[str], direction: str, relationships: set[str], limit: int | None = None, **_: Any):
        out = []
        for edge in self.edges:
            if edge.relationship.value not in relationships:
                continue
            if (direction == "in" and edge.target in node_ids) or (direction == "out" and edge.source in node_ids):
                out.append(edge)
        return out[:limit] if limit else out

    def nodes_by_ids(self, *, node_ids: set[str], **_: Any):
        return [self.nodes[i] for i in node_ids if i in self.nodes]


async def _call(fn: Any, *args: Any, **kwargs: Any) -> Any:
    return fn(*args, **kwargs)


def _stack(store: _FakeStore, ids: set[str]):
    page = [store.nodes[i] for i in ids]
    return asyncio.run(page_agent_stack(store, scan_id="s", tenant_id="t", page_nodes=page, call_store=_call))


def _node(node_id: str, kind: EntityType, risk: float = 0.0) -> UnifiedNode:
    return UnifiedNode(id=node_id, entity_type=kind, label=node_id, risk_score=risk)


def _edge(source: str, target: str, rel: RelationshipType) -> UnifiedEdge:
    return UnifiedEdge(source=source, target=target, relationship=rel)


def test_cve_brings_package_server_and_agent() -> None:
    store = _FakeStore(
        [
            _node("vuln:CVE-1", EntityType.VULNERABILITY, 9.8),
            _node("pkg:a", EntityType.PACKAGE),
            _node("server:s", EntityType.SERVER),
            _node("agent:x", EntityType.AGENT),
        ],
        [
            _edge("pkg:a", "vuln:CVE-1", RelationshipType.VULNERABLE_TO),
            _edge("vuln:CVE-1", "pkg:a", RelationshipType.AFFECTS),
            _edge("server:s", "pkg:a", RelationshipType.DEPENDS_ON),
            _edge("agent:x", "server:s", RelationshipType.USES),
        ],
    )
    result = _stack(store, {"vuln:CVE-1"})
    assert {n.id for n in result.nodes} == {"pkg:a", "server:s", "agent:x"}
    assert {(e.source, e.target) for e in result.edges} >= {("pkg:a", "vuln:CVE-1"), ("server:s", "pkg:a"), ("agent:x", "server:s")}
    assert result.omitted_parent_links == 0


def test_shared_cve_fan_out_is_capped_ranked_and_reported() -> None:
    packages = [_node(f"pkg:{i:02d}", EntityType.PACKAGE, risk=float(i)) for i in range(20)]
    store = _FakeStore(
        [_node("vuln:CVE-2", EntityType.VULNERABILITY), *packages],
        [_edge(p.id, "vuln:CVE-2", RelationshipType.VULNERABLE_TO) for p in packages],
    )
    result = _stack(store, {"vuln:CVE-2"})
    kept = sorted(n.id for n in result.nodes)
    assert len(kept) == STACK_FANOUT
    assert kept == sorted(f"pkg:{i:02d}" for i in range(20 - STACK_FANOUT, 20)), "highest-risk parents are kept"
    assert result.omitted_parent_links == 20 - STACK_FANOUT


def test_unrelated_uses_edge_is_not_a_parent() -> None:
    """A typed hop: a tool that USES a server is not that server's agent."""
    store = _FakeStore(
        [_node("server:s", EntityType.SERVER), _node("tool:t", EntityType.TOOL)],
        [_edge("tool:t", "server:s", RelationshipType.USES)],
    )
    assert _stack(store, {"server:s"}).nodes == []


def test_default_page_shows_a_cve_with_its_full_stack(demo_estate_client: TestClient) -> None:
    payload = demo_estate_client.get("/v1/graph", headers=VIEWER).json()
    types = {str(n["id"]): str(n["entity_type"]) for n in payload["nodes"]}
    parents: dict[str, set[str]] = {}
    for edge in payload["edges"]:
        source, target, rel = str(edge["source"]), str(edge["target"]), str(edge["relationship"])
        if rel == "affects":
            source, target = target, source
        parents.setdefault(target, set()).add(source)

    def chain(node_id: str, wanted: tuple[str, ...]) -> bool:
        if not wanted:
            return True
        return any(types.get(p) in wanted[0].split("|") and chain(p, wanted[1:]) for p in parents.get(node_id, ()))

    cves = [nid for nid, kind in types.items() if kind == "vulnerability"]
    assert cves, "the default page carries no CVEs, so this proves nothing"
    with_package = [c for c in cves if chain(c, ("package",))]
    assert len(with_package) >= len(cves) * 0.9, f"{len(cves) - len(with_package)} of {len(cves)} CVEs have no package"
    assert any(chain(c, ("package", "server", "agent")) for c in cves), "no CVE reaches package -> server -> agent"
    stack = payload["completeness"]["stack_context"]
    assert stack["nodes"] > 0 and stack["fanout_limit"] == STACK_FANOUT
    completeness = payload["completeness"]
    assert completeness["context_nodes"] == len(payload["nodes"]) - completeness["ranked"] - completeness["endpoint_nodes"]
