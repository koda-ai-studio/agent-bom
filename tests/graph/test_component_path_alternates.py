"""One component path per (entry, finding occurrence); other holding chains are evidence.

An image lists every package it ships and a recorded parent also pulls the
child in, so one vulnerable child had two holding chains from the same agent
and became two attack paths. The best chain is the path (strongest evidence
tier, then fewest hops, then highest risk); the rest are counted and sampled
on it.
"""

from __future__ import annotations

from agent_bom.graph.component_paths import MAX_ALTERNATE_CHAINS, derive_component_paths
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType
from agent_bom.graph.types import RelationshipType as R

_VULN = "vuln:CVE-0000-0002"


def _graph(direct_tier: str = "recorded") -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="alternates", tenant_id="t")
    for node_id, kind in (
        ("agent:a", EntityType.AGENT),
        ("server:s", EntityType.SERVER),
        ("image:i", EntityType.CONTAINER),
        ("pkg:parent", EntityType.PACKAGE),
        ("pkg:child", EntityType.PACKAGE),
    ):
        graph.add_node(UnifiedNode(id=node_id, entity_type=kind, label=node_id))
    graph.add_node(UnifiedNode(id=_VULN, entity_type=EntityType.VULNERABILITY, label="CVE", severity="high"))

    def edge(source: str, target: str, rel: R, tier: str = "recorded") -> None:
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=rel, evidence={"source": "test", "tier": tier}))

    edge("agent:a", "server:s", R.USES)
    edge("server:s", "image:i", R.HOSTED_ON)
    edge("image:i", "pkg:parent", R.DEPENDS_ON)
    edge("pkg:parent", "pkg:child", R.DEPENDS_ON)
    edge("image:i", "pkg:child", R.DEPENDS_ON, tier=direct_tier)
    edge("pkg:child", _VULN, R.VULNERABLE_TO)
    return graph


def _derive(graph: UnifiedGraph):
    incoming: dict[str, list] = {}
    outgoing: dict[str, list] = {}
    for e in graph.edges:
        incoming.setdefault(e.target, []).append(e)
        outgoing.setdefault(e.source, []).append(e)
    return derive_component_paths(graph, incoming=incoming, outgoing=outgoing, node_risk=lambda _n: 50.0, path_boost=lambda _h: 0.0)


def test_one_path_per_entry_and_occurrence_keeps_the_shortest_equal_tier_chain() -> None:
    graph = _graph()
    paths = _derive(graph)
    assert len(paths) == 1
    path = paths[0]
    assert path.hops == ["agent:a", "server:s", "image:i", "pkg:child", _VULN]
    assert path.analysis["alternate_chain_count"] == 1
    assert path.analysis["alternate_chains"] == [["agent:a", "server:s", "image:i", "pkg:parent", "pkg:child", _VULN]]
    assert graph.analysis_status["component_paths"].observed["alternate_chains"] == 1


def test_a_stronger_evidence_tier_outranks_a_shorter_chain() -> None:
    paths = _derive(_graph(direct_tier="derived"))
    assert len(paths) == 1
    assert paths[0].hops == ["agent:a", "server:s", "image:i", "pkg:parent", "pkg:child", _VULN]
    assert paths[0].analysis["alternate_chain_count"] == 1


def test_alternate_sample_is_bounded() -> None:
    graph = _graph()
    for index in range(MAX_ALTERNATE_CHAINS + 4):
        mid = f"pkg:mid{index}"
        graph.add_node(UnifiedNode(id=mid, entity_type=EntityType.PACKAGE, label=mid))
        graph.add_edge(UnifiedEdge(source="image:i", target=mid, relationship=R.DEPENDS_ON, evidence={"tier": "recorded"}))
        graph.add_edge(UnifiedEdge(source=mid, target="pkg:child", relationship=R.DEPENDS_ON, evidence={"tier": "recorded"}))
    paths = _derive(graph)
    assert len(paths) == 1
    assert paths[0].analysis["alternate_chain_count"] == MAX_ALTERNATE_CHAINS + 5
    assert len(paths[0].analysis["alternate_chains"]) == MAX_ALTERNATE_CHAINS


def test_alternates_survive_hop_evidence_annotation() -> None:
    from agent_bom.graph.path_evidence import annotate_attack_path_evidence

    graph = _graph()
    path = _derive(graph)[0]
    annotate_attack_path_evidence(path, graph)
    assert path.analysis["alternate_chain_count"] == 1
    assert "status" in path.analysis
