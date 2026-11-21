"""A workload runs the image whose digest it pins: one ``runs`` edge, evidence from both sources."""

from __future__ import annotations

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.component_paths import derive_component_paths
from agent_bom.graph.correlation import CorrelationSnapshot, merge_graph_snapshots
from agent_bom.graph.edge_lookup import _rel_value
from agent_bom.graph.workload_image_runs import link_workload_images

DIGEST = "sha256:" + "7d3e21c4" * 8
OTHER = "sha256:" + "0badc0de" * 8


def _container(node_id: str, source: str, **attributes: object) -> UnifiedNode:
    return UnifiedNode(id=node_id, entity_type=EntityType.CONTAINER, label=node_id, attributes=dict(attributes), data_sources=[source])


def _lab_graph(*, workload_digest: str = DIGEST, image_digest: str = DIGEST) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="scan", tenant_id="acme", created_at="2026-08-30T04:00:00+00:00")
    attrs = {"image_digest": workload_digest} if workload_digest else {"image_ref": "reference-api:latest"}
    graph.add_node(_container("container:iac:api", "kubernetes_iac", **attrs))
    graph.add_node(_container("container:sbom:api", "cyclonedx_sbom", image_digest=image_digest, sbom="sbom.cdx.json"))
    graph.add_node(UnifiedNode(id="package:pillow", entity_type=EntityType.PACKAGE, label="pillow@9.0.0"))
    graph.add_node(UnifiedNode(id="vuln:cve", entity_type=EntityType.VULNERABILITY, label="CVE-2023-4863", severity="high"))
    graph.add_edge(
        UnifiedEdge(
            source="container:sbom:api",
            target="package:pillow",
            relationship=RelationshipType.CONTAINS,
            evidence={"source": "cyclonedx_sbom", "tier": "static_scan"},
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source="package:pillow",
            target="vuln:cve",
            relationship=RelationshipType.VULNERABLE_TO,
            evidence={"source": "bundled_advisory_scanner", "tier": "static_scan"},
        )
    )
    return graph


def _runs(graph: UnifiedGraph) -> list[UnifiedEdge]:
    return [edge for edge in graph.edges if _rel_value(edge) == RelationshipType.RUNS.value]


def test_same_digest_links_workload_to_image_once_with_both_sources() -> None:
    graph = _lab_graph()

    assert link_workload_images(graph) == 1
    assert link_workload_images(graph) == 0  # idempotent

    [edge] = _runs(graph)
    assert (edge.source, edge.target) == ("container:iac:api", "container:sbom:api")
    assert edge.traversable is True
    evidence = edge.evidence
    assert evidence["basis"] == "image_digest_match"
    assert evidence["image_digest"] == DIGEST
    assert evidence["tier"] == "derived"
    assert evidence["derived_via"] == ["image_digest"]
    assert evidence["workload_node_id"] == "container:iac:api"
    assert evidence["image_node_id"] == "container:sbom:api"
    assert evidence["workload_sources"] == ["kubernetes_iac"]
    assert evidence["image_sources"] == ["cyclonedx_sbom"]


def test_different_digest_gives_no_edge() -> None:
    graph = _lab_graph(image_digest=OTHER)
    assert link_workload_images(graph) == 0
    assert _runs(graph) == []


def test_tag_only_workload_gives_no_edge() -> None:
    graph = _lab_graph(workload_digest="")
    assert link_workload_images(graph) == 0
    assert _runs(graph) == []


def test_recorded_container_kind_wins_over_source() -> None:
    graph = _lab_graph()
    graph.nodes["container:iac:api"].attributes["container_kind"] = "image"
    # Two images with one digest are the same artifact; nothing runs anything.
    assert link_workload_images(graph) == 0


def test_unclassified_container_never_links() -> None:
    graph = _lab_graph()
    graph.nodes["container:iac:api"].data_sources = ["unknown_collector"]
    assert link_workload_images(graph) == 0


def test_path_reaches_the_cve_through_runs_without_a_second_entry() -> None:
    graph = _lab_graph()
    # The IaC projection also records the workload's composition directly.
    graph.add_edge(
        UnifiedEdge(
            source="container:iac:api",
            target="package:pillow",
            relationship=RelationshipType.CONTAINS,
            evidence={"source": "kubernetes_iac_sbom_projection", "tier": "modeled_infrastructure"},
        )
    )

    def derive() -> list:
        incoming: dict[str, list[UnifiedEdge]] = {}
        outgoing: dict[str, list[UnifiedEdge]] = {}
        for edge in graph.edges:
            incoming.setdefault(edge.target, []).append(edge)
            outgoing.setdefault(edge.source, []).append(edge)
        return derive_component_paths(graph, incoming=incoming, outgoing=outgoing, node_risk=lambda node: 0.0, path_boost=lambda hops: 0.0)

    before = derive()
    # Before linking, the image and the workload each start a path to the same occurrence.
    assert sorted(path.source for path in before) == ["container:iac:api", "container:sbom:api"]

    link_workload_images(graph)
    after = derive()
    # The image is now held by the workload that runs it: one entry, one path.
    assert [path.source for path in after] == ["container:iac:api"]
    assert after[0].target == "vuln:cve"


def test_runs_only_path_reaches_the_cve() -> None:
    graph = _lab_graph()
    link_workload_images(graph)
    incoming: dict[str, list[UnifiedEdge]] = {}
    for edge in graph.edges:
        incoming.setdefault(edge.target, []).append(edge)
    [path] = derive_component_paths(graph, incoming=incoming, outgoing={}, node_risk=lambda node: 0.0, path_boost=lambda hops: 0.0)
    assert path.hops == ["container:iac:api", "container:sbom:api", "package:pillow", "vuln:cve"]
    assert path.edges[0] == "runs"


def test_correlation_merge_emits_runs_between_snapshot_sources() -> None:
    sbom = UnifiedGraph(scan_id="sbom-scan", tenant_id="acme", created_at="2026-08-30T04:01:00+00:00")
    sbom.add_node(_container("container:sbom:api", "cyclonedx_sbom", image_digest=DIGEST))
    iac = UnifiedGraph(scan_id="iac-scan", tenant_id="acme", created_at="2026-08-30T04:02:00+00:00")
    iac.add_node(_container("container:iac:api", "kubernetes_iac", image_digest=DIGEST))

    result = merge_graph_snapshots(
        correlation_id="corr",
        tenant_id="acme",
        snapshots=[CorrelationSnapshot.from_graph(sbom), CorrelationSnapshot.from_graph(iac)],
    )

    [edge] = _runs(result.graph)
    assert edge.target == "container:sbom:api"
    assert result.manifest["output"]["edge_count"] == len(result.graph.edges) == 1
