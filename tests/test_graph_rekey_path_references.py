"""Re-keying a node rewrites every attack path and interaction risk that names it."""

from __future__ import annotations

import pytest

from agent_bom.graph.asset_canonicalize import canonicalize_assets
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import AttackPath, InteractionRisk, UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.store_backed import open_store_backed_unified_graph
from agent_bom.graph.types import EntityType

_K8S = {"cluster_id": "prod", "namespace": "ns", "kubernetes_kind": "Deployment", "kubernetes_name": "api"}


def _container(node_id: str, **attributes: object) -> UnifiedNode:
    return UnifiedNode(id=node_id, entity_type=EntityType.CONTAINER, label="api", attributes={**_K8S, **attributes})


def _seed(graph: UnifiedGraph) -> None:
    graph.add_node(UnifiedNode(id="agent:x", entity_type=EntityType.AGENT, label="x"))
    graph.add_node(_container("container:c1/ns/api"))
    graph.attack_paths.append(
        AttackPath(
            source="agent:x",
            target="container:c1/ns/api",
            hops=["agent:x", "container:c1/ns/api"],
            edges=["uses"],
            composite_risk=5.0,
            hop_evidence=[{"source_node_id": "agent:x", "target_node_id": "container:c1/ns/api", "relationship": "uses"}],
        )
    )
    graph.attack_paths.append(
        AttackPath(
            source="agent:x", target="container:finding/api", hops=["agent:x", "container:finding/api"], edges=["uses"], composite_risk=7.0
        )
    )
    graph.interaction_risks.append(
        InteractionRisk(pattern="shared", agents=["x"], risk_score=8.0, description="", agent_node_ids=["container:c1/ns/api"])
    )
    graph.add_node(_container("container:finding/api", kubernetes_uid="uid-1"))


def assert_paths_reference_nodes(graph: UnifiedGraph) -> None:
    for path in graph.attack_paths:
        missing = [hop for hop in (path.source, path.target, *path.hops) if not graph.has_node(hop)]
        assert not missing, (path.hops, missing)
        assert len(path.edges) <= max(len(path.hops) - 1, 0)
        for index, receipt in enumerate(path.hop_evidence):
            assert (receipt["source_node_id"], receipt["target_node_id"]) == (path.hops[index], path.hops[index + 1])


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_canonicalization_rewrites_attack_paths_and_risks(backend: str) -> None:
    if backend == "memory":
        graph = UnifiedGraph()
    else:
        graph = open_store_backed_unified_graph(backend=backend, tenant_id="rekey-paths", capacity=2, page_size=2)
    _seed(graph)
    mapping = canonicalize_assets(graph)
    canonical = mapping["container:c1/ns/api"]
    assert canonical.startswith("container:") and canonical != "container:c1/ns/api"
    assert_paths_reference_nodes(graph)
    # Two paths that now name the same hops collapse to one, keeping the riskier.
    assert len(graph.attack_paths) == 1
    assert graph.attack_paths[0].hops == ["agent:x", canonical]
    assert graph.attack_paths[0].composite_risk == 7.0
    assert graph.interaction_risks[0].agent_node_ids == [canonical]


def test_interaction_risk_round_trips_agent_node_ids() -> None:
    risk = InteractionRisk(pattern="p", agents=["a"], risk_score=1.0, description="", agent_node_ids=["agent:fleet:a"])
    assert InteractionRisk.from_dict(risk.to_dict()).agent_node_ids == ["agent:fleet:a"]


def test_built_graph_attack_path_hops_are_graph_nodes() -> None:
    from agent_bom.demo_estate.compute_identity_lane import compute_lane_report
    from agent_bom.graph.path_derivation import _derived_attack_paths

    graph = build_unified_graph_from_report(compute_lane_report())
    assert_paths_reference_nodes(graph)
    graph.attack_paths = _derived_attack_paths(graph)
    assert graph.attack_paths
    assert_paths_reference_nodes(graph)


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_rekeyed_stored_edge_gets_identity_for_its_new_endpoints(backend):
    from contextlib import nullcontext

    from agent_bom.canonical_ids import canonical_graph_edge_id
    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.types import RelationshipType

    context = nullcontext(UnifiedGraph()) if backend == "memory" else open_store_backed_unified_graph(backend="sqlite", capacity=1)
    with context as graph:
        for name in ("old", "target"):
            graph.add_node(UnifiedNode(id=name, entity_type=EntityType.AGENT if name == "old" else EntityType.SERVER, label=name))
        edge = UnifiedEdge.from_dict({"source": "old", "target": "target", "relationship": "uses", "canonical_id": "historical-receipt"})
        assert edge.with_endpoints("old", "target").canonical_id == "historical-receipt"
        graph.add_edge(edge)
        graph.rekey_nodes({"old": "new"})
        result = list(graph.edges)
        assert len(result) == 1
        assert result[0].canonical_id == canonical_graph_edge_id("new", "target", RelationshipType.USES.value)
        assert edge.canonical_id == "historical-receipt"
