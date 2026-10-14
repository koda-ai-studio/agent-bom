"""Per-occurrence applicability: reachability and VEX live on each vulnerable edge.

A CVE node is shared by every package that carries it. Reachability and VEX
are facts about one occurrence (asset -> CVE), so they ride the primary
``vulnerable_to`` edge and path derivation reads them there. The CVE node only
keeps an aggregate that never depends on report row order.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.path_derivation import _derived_attack_paths
from agent_bom.graph.types import EntityType, RelationshipType

CVE = "CVE-2023-32681"
VULN = f"vuln:{CVE}"
REQUESTS = "pkg:pypi:requests@2.28.0"
LAB = Path(__file__).resolve().parents[2] / "examples" / "reference-evidence-lab" / "generated" / "correlation-proof.json"


def _scan(tmp_path: Path, *args: str) -> dict:
    out = tmp_path / "report.json"
    result = CliRunner().invoke(main, ["scan", "--offline", "--demo", "-f", "json", "-q", *args, "-o", str(out)])
    assert out.is_file(), result.output
    return json.loads(out.read_text())


@pytest.fixture(scope="module")
def demo_report(tmp_path_factory: pytest.TempPathFactory) -> dict:
    return _scan(tmp_path_factory.mktemp("demo"))


@pytest.fixture(scope="module")
def vex_report(tmp_path_factory: pytest.TempPathFactory) -> dict:
    tmp = tmp_path_factory.mktemp("vex")
    vex = tmp / "vex.json"
    vex.write_text(
        json.dumps(
            {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "@id": "https://example.invalid/vex/1",
                "author": "test",
                "timestamp": "2026-10-13T00:00:00Z",
                "version": 1,
                "statements": [
                    {
                        "vulnerability": {"name": CVE},
                        "products": [{"@id": "pkg:pypi/requests@2.28.0"}],
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_in_execute_path",
                    }
                ],
            }
        )
    )
    return _scan(tmp, "--vex", str(vex))


def _occurrence_basis(path) -> list[str]:
    """The applicability basis a served path carries, before hop-evidence adjustments.

    Serving appends hop-evidence reason codes and may move the verdict (missing
    receipts -> unknown, complete receipts -> confirmed); the occurrence's own
    basis stays the prefix.
    """
    return [item for item in path.reachability_basis if item not in _HOP_EVIDENCE_REASONS]


_HOP_EVIDENCE_REASONS = {"incomplete_hop_evidence", "directed_provenance_backed_hops", "stale_evidence_allowed"}


def _paths_to(graph: UnifiedGraph, target: str) -> list:
    return [path for path in _derived_attack_paths(graph) if path.target == target]


def _occurrence_edge(graph: UnifiedGraph, source: str, target: str) -> UnifiedEdge:
    return next(
        edge
        for edge in graph.edges
        if edge.source == source and edge.target == target and edge.relationship == RelationshipType.VULNERABLE_TO
    )


def test_vex_not_affected_occurrence_has_no_attack_path(vex_report: dict) -> None:
    graph = build_unified_graph_from_report(copy.deepcopy(vex_report), scan_id="vex")

    applicability = _occurrence_edge(graph, REQUESTS, VULN).evidence["applicability"]
    assert applicability["vex_status"] == "not_affected"
    assert applicability["vex_justification"] == "vulnerable_code_not_in_execute_path"
    assert graph.nodes[VULN].attributes["vex_status"] == "not_affected"
    assert _paths_to(graph, VULN) == []

    status = graph.analysis_status["component_paths"].to_dict()
    assert status["observed"]["vex_excluded"] == 3


def test_vex_status_matches_the_finding(vex_report: dict) -> None:
    finding = next(row for row in vex_report["findings"] if row.get("cve_id") == CVE)
    graph = build_unified_graph_from_report(copy.deepcopy(vex_report), scan_id="vex")
    applicability = _occurrence_edge(graph, REQUESTS, VULN).evidence["applicability"]
    assert applicability["vex_status"] == finding["evidence"]["vex_status"]


def test_without_vex_the_same_occurrence_keeps_its_paths(demo_report: dict) -> None:
    graph = build_unified_graph_from_report(copy.deepcopy(demo_report), scan_id="demo")
    assert sorted(path.source for path in _paths_to(graph, VULN)) == ["agent:cursor", "agent:data-pipeline", "agent:langchain-service"]
    assert graph.analysis_status["component_paths"].to_dict()["observed"]["vex_excluded"] == 0


def _split_occurrences(report: dict, *, unlikely_first: bool) -> dict:
    """Two packages carry the same CVE: one reachable, one disproven."""
    rep = copy.deepcopy(report)
    row = next(item for item in rep["blast_radius"] if item["vulnerability_id"] == CVE)
    others = [item for item in rep["blast_radius"] if item["vulnerability_id"] != CVE]
    shell = next(server for agent in rep["agents"] for server in agent["mcp_servers"] if server["name"] == "shell-runner-server")
    template = next(pkg for pkg in shell["packages"] if pkg["name"] == "requests")
    vendored = {**copy.deepcopy(template), "version": "2.27.0", "purl": "pkg:pypi/requests@2.27.0"}
    shell["packages"] = [pkg for pkg in shell["packages"] if pkg["name"] != "requests"] + [vendored]

    likely = copy.deepcopy(row)
    likely.update(affected_agents=["langchain-service", "data-pipeline"], affected_servers=["vector-db-server", "etl-server"])
    unlikely = copy.deepcopy(row)
    unlikely.update(
        package="requests@2.27.0",
        package_version="2.27.0",
        package_purl="pkg:pypi/requests@2.27.0",
        canonical_id="occurrence-unlikely",
        reachability="unlikely",
        reachability_basis=["dependency_unreachable"],
        dependency_reachable=False,
        affected_agents=["cursor"],
        affected_servers=["shell-runner-server"],
    )
    rep["blast_radius"] = others + ([unlikely, likely] if unlikely_first else [likely, unlikely])
    return rep


@pytest.mark.parametrize("unlikely_first", [True, False])
def test_opposite_reachability_occurrences_keep_their_own_verdicts(demo_report: dict, unlikely_first: bool) -> None:
    graph = build_unified_graph_from_report(_split_occurrences(demo_report, unlikely_first=unlikely_first), scan_id="split")

    assert _occurrence_edge(graph, REQUESTS, VULN).evidence["applicability"]["verdict"] == "likely"
    assert _occurrence_edge(graph, "pkg:pypi:requests@2.27.0", VULN).evidence["applicability"]["verdict"] == "unlikely"
    paths = _paths_to(graph, VULN)
    assert sorted(path.source for path in paths) == ["agent:data-pipeline", "agent:langchain-service"]
    assert {tuple(_occurrence_basis(path)) for path in paths} == {("dependency_path", "direct_agent_dependency")}

    node = graph.nodes[VULN].attributes
    assert node["reachability"] == "likely"
    assert node["occurrence_verdicts"] == {"likely": 1, "unlikely": 1}


def _api_findings(report: dict) -> dict[str, dict]:
    """Rows as ``/v1/findings`` collects them for a finished scan job."""
    from agent_bom.api.finding_collection import collect_scan_findings
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest

    job = ScanJob(
        job_id="job",
        tenant_id="default",
        request=ScanRequest(),
        status=JobStatus.DONE,
        created_at="2026-01-01T00:00:00+00:00",
        result=copy.deepcopy(report),
    )
    return {row["id"]: row for row in collect_scan_findings(job)}


def test_paths_carry_the_occurrence_finding_ids(demo_report: dict) -> None:
    api_rows = _api_findings(demo_report)
    graph = build_unified_graph_from_report(copy.deepcopy(demo_report), scan_id="demo")

    cve_paths = [path for path in _derived_attack_paths(graph) if graph.nodes[path.target].entity_type == EntityType.VULNERABILITY]
    assert cve_paths
    for path in cve_paths:
        assert path.finding_ids, path.hops
        assert set(path.finding_ids) <= set(api_rows), (path.hops, path.finding_ids)


def test_findings_api_edge_and_path_agree_on_applicability(vex_report: dict) -> None:
    graph = build_unified_graph_from_report(copy.deepcopy(vex_report), scan_id="vex")
    paths = _derived_attack_paths(graph)
    checked = 0
    for finding in _api_findings(vex_report).values():
        cve = finding.get("cve_id")
        holder = finding.get("node_id")
        if not cve or not holder or (holder, f"vuln:{cve}") not in {(e.source, e.target) for e in graph.edges}:
            continue
        checked += 1
        applicability = _occurrence_edge(graph, holder, f"vuln:{cve}").evidence["applicability"]
        assert applicability["verdict"] == finding["reachability"], cve
        assert applicability.get("vex_status") == (finding.get("evidence") or {}).get("vex_status"), cve
        served = {tuple(_occurrence_basis(path)) for path in paths if path.target == f"vuln:{cve}" and holder in path.hops}
        if applicability.get("vex_status") in {"not_affected", "fixed"} or applicability["verdict"] == "unlikely":
            assert served == set(), cve
        else:
            assert served == {tuple(applicability["basis"])}, cve
    assert checked == len([row for row in vex_report["blast_radius"]])


def _lab_graph() -> UnifiedGraph:
    data = json.loads(LAB.read_text())
    return UnifiedGraph.from_dict(data["capture_fixture"]["graph"])


def test_reference_lab_container_and_sbom_cve_occurrence_gets_paths() -> None:
    graph = _lab_graph()
    vuln = "vulnerability:sbom:cve-2023-4863"
    chains = sorted(tuple(path.hops) for path in _paths_to(graph, vuln))
    assert chains == [
        ("container:iac:reference-api", "package:iac:pillow", vuln),
        ("container:sbom:reference-api", "package:iac:pillow", vuln),
        ("source:pinned-package", "package:iac:pillow", vuln),
    ]
    for path in _paths_to(graph, vuln):
        assert path.finding_ids == ["reference-finding-cve-2023-4863"]
        assert _occurrence_basis(path) == ["insufficient_evidence"]
        assert path.composite_risk <= 39.0


def _estate_graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="estate", tenant_id="default")

    def node(node_id: str, entity_type: EntityType, **attrs: object) -> None:
        graph.add_node(UnifiedNode(id=node_id, entity_type=entity_type, label=node_id, attributes=dict(attrs)))

    def edge(source: str, target: str, rel: RelationshipType, **evidence: object) -> None:
        graph.add_edge(
            UnifiedEdge(source=source, target=target, relationship=rel, evidence={"source": "test", "tier": "static_scan", **evidence})
        )

    node("env:prod", EntityType.ENVIRONMENT)
    node("workload:api", EntityType.CONTAINER)
    node("image:api", EntityType.CONTAINER)
    node("pkg:libwebp", EntityType.PACKAGE)
    node("vuln:img", EntityType.VULNERABILITY, finding_id="finding-img", reachability="likely", reachability_basis=["package_reachable"])
    edge("env:prod", "workload:api", RelationshipType.CONTAINS)
    edge("env:prod", "pkg:libwebp", RelationshipType.CONTAINS)
    edge("workload:api", "image:api", RelationshipType.DEPENDS_ON)
    edge("image:api", "pkg:libwebp", RelationshipType.DEPENDS_ON)
    edge("pkg:libwebp", "vuln:img", RelationshipType.VULNERABLE_TO)
    return graph


def test_container_image_cve_gets_one_path_from_the_workload_not_the_environment() -> None:
    graph = _estate_graph()
    paths = _paths_to(graph, "vuln:img")
    assert [tuple(path.hops) for path in paths] == [("workload:api", "image:api", "pkg:libwebp", "vuln:img")]
    assert paths[0].edges == ["depends_on", "depends_on", "vulnerable_to"]
    assert paths[0].finding_ids == ["finding-img"]
    assert _occurrence_basis(paths[0]) == ["package_reachable"]


def test_container_cve_with_vex_fixed_on_the_edge_is_excluded_and_counted() -> None:
    graph = _estate_graph()
    _occurrence_edge(graph, "pkg:libwebp", "vuln:img").evidence["applicability"] = {"verdict": "likely", "vex_status": "fixed"}
    assert _paths_to(graph, "vuln:img") == []
    assert graph.analysis_status["component_paths"].to_dict()["observed"]["vex_excluded"] == 1


def test_sbom_sourced_package_cve_gets_a_path() -> None:
    report = {
        "agents": [
            {
                "name": "sbom:api",
                "agent_type": "custom",
                "source": "sbom",
                "metadata": {"sbom_import": {"source": "sbom", "format": "cyclonedx"}},
                "mcp_servers": [
                    {
                        "name": "api",
                        "surface": "sbom",
                        "command": "sbom",
                        "packages": [{"name": "pillow", "version": "9.0.0", "ecosystem": "pypi", "purl": "pkg:pypi/pillow@9.0.0"}],
                    }
                ],
            }
        ],
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2023-4863",
                "canonical_id": "finding-sbom-pillow",
                "severity": "high",
                "package": "pillow@9.0.0",
                "package_name": "pillow",
                "package_version": "9.0.0",
                "ecosystem": "pypi",
                "package_purl": "pkg:pypi/pillow@9.0.0",
                "affected_agents": [],
                "affected_servers": ["api"],
                "reachability": "unknown",
                "reachability_basis": ["declaration_only"],
            }
        ],
    }
    graph = build_unified_graph_from_report(report, scan_id="sbom")
    paths = _paths_to(graph, "vuln:CVE-2023-4863")
    assert len(paths) == 1
    hops = paths[0].hops
    assert graph.nodes[hops[0]].entity_type == EntityType.SOURCE_FILE
    assert graph.nodes[hops[-2]].entity_type == EntityType.PACKAGE
    assert paths[0].finding_ids == ["finding-sbom-pillow"]
