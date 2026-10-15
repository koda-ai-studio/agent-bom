"""KEV and exploit signals recorded on a finding must reach its graph node.

Attack-path ranking orders by ``is_kev`` read from the path's finding nodes, so a
projection that drops the flag silently demotes every exploited-in-the-wild path.
"""

from __future__ import annotations

import pytest

from agent_bom.demo_estate.enterprise_composition import build_demo_estate
from agent_bom.demo_estate.enterprise_findings import build_estate_findings
from agent_bom.demo_estate.estate_graph import project_estate_into_graph
from agent_bom.graph.attack_path_queue_rank import path_is_kev
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.finding_row_projection import project_finding_rows
from agent_bom.graph.types import EntityType


def test_finding_row_projection_carries_kev_and_exploit_signals() -> None:
    graph = UnifiedGraph(scan_id="kev", tenant_id="t")
    row = {
        "id": "f-1",
        "finding_type": "CVE",
        "source": "SBOM",
        "severity": "high",
        "title": "CVE-2023-4863: pillow@9.0.0",
        "cve_id": "CVE-2023-4863",
        "is_kev": True,
        "epss_score": 0.67,
        "cvss_score": 8.8,
        "fixed_version": "10.0.1",
        "asset": {"name": "pillow@9.0.0", "asset_type": "package", "identifier": "pkg:pypi/pillow@9.0.0"},
    }
    project_finding_rows(graph, [row])
    vulns = [n for n in graph.nodes.values() if n.entity_type == EntityType.VULNERABILITY]
    assert len(vulns) == 1
    attrs = vulns[0].attributes
    assert attrs["vulnerability_id"] == "CVE-2023-4863"
    assert attrs["is_kev"] is True
    assert attrs["epss_score"] == 0.67
    assert attrs["cvss_score"] == 8.8
    assert attrs["fixed_version"] == "10.0.1"


@pytest.fixture(scope="module")
def estate_graph_and_findings():
    estate = build_demo_estate(tenant_id="default")
    findings = build_estate_findings(estate)
    graph = UnifiedGraph(scan_id="estate-kev", tenant_id="default")
    project_estate_into_graph(graph, estate, findings=findings)
    return graph, findings


def test_estate_projection_carries_kev_for_every_kev_finding(estate_graph_and_findings) -> None:
    graph, findings = estate_graph_and_findings
    kev_findings = [f for f in findings if f.is_kev]
    assert kev_findings, "the demo estate must carry KEV findings for this check to mean anything"
    for finding in kev_findings:
        node = graph.nodes[f"vuln:demo-estate:{finding.id}"]
        assert node.attributes.get("is_kev") is True, finding.id
        assert node.attributes.get("vulnerability_id") == finding.vulnerability_id
        path = AttackPath(source="a", target=node.id, hops=[node.id], edges=[], composite_risk=1.0, summary="")
        assert path_is_kev(path, graph.nodes)
    non_kev = next(f for f in findings if not f.is_kev and f.finding_type.value == "CVE")
    assert graph.nodes[f"vuln:demo-estate:{non_kev.id}"].attributes.get("is_kev") is False
