"""Image-level findings retain structural paths without inventing deployment."""

import pytest

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from tests.graph.test_component_path_alternates import _derive


@pytest.mark.parametrize("kind", [EntityType.CONTAINER, EntityType.PACKAGE])
def test_standalone_image_finding_has_structural_path(kind):
    graph = UnifiedGraph(scan_id="image-scan", tenant_id="one")
    graph.add_node(UnifiedNode(id="asset", entity_type=kind, label="fixture"))
    graph.add_node(UnifiedNode(id="finding", entity_type=EntityType.VULNERABILITY, label="CVE-2023-4863", severity="critical"))
    graph.add_edge(UnifiedEdge(source="asset", target="finding", relationship=RelationshipType.VULNERABLE_TO))
    paths = _derive(graph)
    if kind == EntityType.PACKAGE:
        assert paths == []
    else:
        assert len(paths) == 1
        assert paths[0].hops == ["asset", "finding"]
        assert paths[0].reachability == "unknown"
        assert paths[0].credential_exposure == []


@pytest.mark.parametrize("mixed", [False, True])
def test_image_without_agent_entrypoint_is_not_marked_unreachable(mixed):
    from agent_bom.discovery.carriers import build_image_carrier
    from agent_bom.graph.blast_reach import apply_dependency_reachability_to_blast_radii
    from agent_bom.graph.builder import build_unified_graph_from_report
    from agent_bom.graph.snapshot_paths import materialize_snapshot_paths
    from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability
    from agent_bom.output.graph_evidence import graph_evidence_sections

    vuln = Vulnerability(id="CVE-2023-4863", summary="fixture", severity=Severity.CRITICAL)
    package = Package(name="libwebp", version="1.2.0", ecosystem="apk", vulnerabilities=[vuln])
    image = build_image_carrier("fixture:1", [package])
    row = BlastRadius(
        vulnerability=vuln,
        package=package,
        affected_agents=[image],
        affected_servers=image.mcp_servers,
        exposed_credentials=[],
        exposed_tools=[],
    )
    agents = [image]
    if mixed:
        other = Package(name="other", version="1", ecosystem="npm", vulnerabilities=[vuln])
        agents.append(
            Agent(
                name="other-agent",
                agent_type=AgentType.CUSTOM,
                config_path="other.json",
                mcp_servers=[MCPServer(name="other", packages=[other])],
            )
        )
    assert apply_dependency_reachability_to_blast_radii([row], agents) == 0
    assert row.dependency_reachable is None
    report = AIBOMReport(agents=agents, blast_radii=[row])
    graph = build_unified_graph_from_report(graph_evidence_sections(report))
    paths = materialize_snapshot_paths(graph)
    assert any(path for path in paths if "container:image:fixture:1" in path.path.hops)
