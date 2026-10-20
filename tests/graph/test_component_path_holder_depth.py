"""A transitive package inside a hosted image still chains back to the agent.

agent -> server -> workload -> image -> service package -> SDK -> parent -> child
is seven holding edges; a five-edge budget cut it at the workload and marked
the whole snapshot's component paths LIMITED.
"""

from __future__ import annotations

from agent_bom.graph.analysis import GraphAnalysisState
from agent_bom.graph.component_paths import MAX_HOLDER_DEPTH, derive_component_paths
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType
from agent_bom.graph.types import RelationshipType as R


def _graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="holder-depth", tenant_id="t")
    chain = [
        ("agent:a", EntityType.AGENT),
        ("server:s", EntityType.SERVER),
        ("workload:w", EntityType.CONTAINER),
        ("image:i", EntityType.CONTAINER),
        ("pkg:svc", EntityType.PACKAGE),
        ("pkg:sdk", EntityType.PACKAGE),
        ("pkg:parent", EntityType.PACKAGE),
        ("pkg:child", EntityType.PACKAGE),
    ]
    for node_id, kind in chain:
        graph.add_node(UnifiedNode(id=node_id, entity_type=kind, label=node_id))
    graph.add_node(UnifiedNode(id="vuln:CVE-0000-0001", entity_type=EntityType.VULNERABILITY, label="CVE", severity="high"))
    rels = [R.USES, R.HOSTED_ON, R.DEPENDS_ON, R.DEPENDS_ON, R.DEPENDS_ON, R.DEPENDS_ON, R.DEPENDS_ON]
    for ((source, _), (target, _)), rel in zip(zip(chain, chain[1:]), rels, strict=True):
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=rel))
    graph.add_edge(UnifiedEdge(source="pkg:child", target="vuln:CVE-0000-0001", relationship=R.VULNERABLE_TO))
    return graph


def test_seven_edge_holder_chain_reaches_the_agent_within_budget() -> None:
    assert MAX_HOLDER_DEPTH >= 7
    graph = _graph()
    incoming: dict[str, list] = {}
    outgoing: dict[str, list] = {}
    for edge in graph.edges:
        incoming.setdefault(edge.target, []).append(edge)
        outgoing.setdefault(edge.source, []).append(edge)
    paths = derive_component_paths(graph, incoming=incoming, outgoing=outgoing, node_risk=lambda _n: 50.0, path_boost=lambda _h: 0.0)
    assert [p.hops[0] for p in paths] == ["agent:a"]
    assert paths[0].hops[-2:] == ["pkg:child", "vuln:CVE-0000-0001"]
    assert graph.analysis_status["component_paths"].status is GraphAnalysisState.COMPLETE
