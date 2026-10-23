"""GPU stack components from a host scan carry their NVIDIA CPE into SBOMs, JSON and the graph."""

from __future__ import annotations

from pathlib import Path

from agent_bom.filesystem import scan_disk_path_native
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, ServerSurface
from agent_bom.output.cyclonedx_fmt import to_cyclonedx
from agent_bom.output.json_fmt import to_json
from agent_bom.output.spdx2_fmt import to_spdx2
from agent_bom.output.spdx_fmt import to_spdx

DRIVER_CPE = "cpe:2.3:a:nvidia:gpu_display_driver:550.54.15:*:*:*:*:linux:*:*"


def _report(root: Path) -> AIBOMReport:
    version = root / "proc/driver/nvidia/version"
    version.parent.mkdir(parents=True)
    version.write_text("NVRM version: NVIDIA UNIX x86_64 Kernel Module  550.54.15  Tue Mar  5 22:23:56 UTC 2024\n")
    server = MCPServer(name=f"fs:{root}", surface=ServerSurface.FILESYSTEM, packages=scan_disk_path_native(root))
    agent = Agent(name="filesystem:gpu-host", agent_type=AgentType.CUSTOM, config_path=str(root), source="filesystem", mcp_servers=[server])
    return AIBOMReport(agents=[agent])


def test_cyclonedx_and_spdx_carry_driver_cpe(tmp_path: Path) -> None:
    report = _report(tmp_path)
    (component,) = [c for c in to_cyclonedx(report)["components"] if c["name"] == "nvidia-gpu-display-driver"]
    assert component["cpe"] == DRIVER_CPE
    assert component["purl"] == "pkg:generic/nvidia/nvidia-gpu-display-driver@550.54.15"
    (spdx2,) = [p for p in to_spdx2(report)["packages"] if p["name"] == "nvidia-gpu-display-driver"]
    assert {"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": DRIVER_CPE} in spdx2["externalRefs"]
    (spdx3,) = [e for e in to_spdx(report)["@graph"] if e.get("name") == "nvidia-gpu-display-driver" and "externalIdentifier" in e]
    assert {"type": "ExternalIdentifier", "externalIdentifierType": "cpe23", "identifier": DRIVER_CPE} in spdx3["externalIdentifier"]


def test_graph_links_host_to_gpu_driver_node(tmp_path: Path) -> None:
    from agent_bom.graph.builder import build_unified_graph_from_report

    doc = to_json(_report(tmp_path))
    (package,) = [p for p in doc["agents"][0]["mcp_servers"][0]["packages"] if p["name"] == "nvidia-gpu-display-driver"]
    assert package["cpe"] == DRIVER_CPE
    assert package["discovery_provenance"]["source"] == "loaded-kernel-module"

    graph = build_unified_graph_from_report(doc)
    (node,) = [n for n in graph.nodes.values() if n.entity_type.value == "package" and n.label == "nvidia-gpu-display-driver@550.54.15"]
    assert node.attributes["cpe"] == DRIVER_CPE
    (host,) = [n for n in graph.nodes.values() if n.entity_type.value == "agent" and n.label == "filesystem:gpu-host"]
    parents = {edge.source for edge in graph.edges if edge.target == node.id}
    assert parents and all(any(e.source == host.id and e.target == parent for e in graph.edges) for parent in parents)
