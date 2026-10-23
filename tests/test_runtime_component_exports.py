"""Runtime components carry their CPE identity into every SBOM/report format."""

from __future__ import annotations

from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer
from agent_bom.output.cyclonedx_fmt import to_cyclonedx
from agent_bom.output.json_fmt import to_json
from agent_bom.output.spdx2_fmt import to_spdx2
from agent_bom.output.spdx_fmt import to_spdx
from agent_bom.parsers.image_runtimes import runtime_packages_from_config

CPE = "cpe:2.3:a:php:php:8.3.30:*:*:*:*:*:*:*"


def _report() -> AIBOMReport:
    (php,) = runtime_packages_from_config({"config": {"Env": ["PHP_VERSION=8.3.30"]}})
    server = MCPServer(name="php:8.3", command="docker", packages=[php])
    return AIBOMReport(agents=[Agent(name="image", agent_type=AgentType.CUSTOM, config_path="php:8.3", mcp_servers=[server])])


def test_cyclonedx_component_has_cpe() -> None:
    (component,) = [c for c in to_cyclonedx(_report())["components"] if c["name"] == "php"]
    assert component["cpe"] == CPE
    assert component["purl"] == "pkg:generic/php/php@8.3.30"


def test_spdx2_package_has_cpe23_security_ref() -> None:
    (package,) = [p for p in to_spdx2(_report())["packages"] if p["name"] == "php"]
    assert {"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": CPE} in package["externalRefs"]


def test_spdx3_package_has_cpe23_identifier() -> None:
    (package,) = [e for e in to_spdx(_report())["@graph"] if e.get("name") == "php" and "externalIdentifier" in e]
    assert {"type": "ExternalIdentifier", "externalIdentifierType": "cpe23", "identifier": CPE} in package["externalIdentifier"]


def test_json_report_package_has_cpe_and_provenance() -> None:
    doc = to_json(_report())
    (package,) = [p for p in doc["agents"][0]["mcp_servers"][0]["packages"] if p["name"] == "php"]
    assert package["cpe"] == CPE
    assert package["discovery_provenance"]["source"] == "image-env"


def test_graph_links_image_to_runtime_component_with_cpe() -> None:
    from agent_bom.graph.builder import build_unified_graph_from_report

    graph = build_unified_graph_from_report(to_json(_report()))
    (node,) = [n for n in graph.nodes.values() if n.entity_type.value == "package" and n.label == "php@8.3.30"]
    assert node.attributes["cpe"] == CPE
    assert node.attributes["discovery_provenance"]["source"] == "image-env"
    assert any(edge.target == node.id for edge in graph.edges)
