"""GitHub rejects a whole SARIF upload over one result without a physical location.

Real upload errors this guards: ``buildRelatedLocations: expected physical
location`` and ``locationFromSarifResult: expected a physical location``.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import Agent, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.output.sarif import to_sarif
from tests.test_sarif_schema_2_1_0 import _full_chain_report, _multi_finding_report

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("check_sarif_locations", ROOT / "scripts" / "check_sarif_locations.py")
assert _spec and _spec.loader
checker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checker)


def _vulnerable_blast(config_path: str) -> AIBOMReport:
    vuln = Vulnerability(id="CVE-2026-97687", summary="s", severity=Severity.HIGH, fixed_version="2.8.0")
    pkg = Package(name="urllib3", version="2.7.0", ecosystem="pypi", vulnerabilities=[vuln])
    agent = Agent(name="agent", agent_type="cli", config_path=config_path, mcp_servers=[])
    blast = BlastRadius(
        vulnerability=vuln, package=pkg, affected_agents=[agent], affected_servers=[], exposed_credentials=[], exposed_tools=[]
    )
    return AIBOMReport(agents=[agent], blast_radii=[blast])


def _malicious_without_a_file() -> AIBOMReport:
    pkg = Package(name="evil", version="1.0.0", ecosystem="npm", is_malicious=True, malicious_reason="typosquat")
    server = MCPServer(name="tools", command="npx", packages=[pkg])
    return AIBOMReport(agents=[Agent(name="a", agent_type="cli", config_path="/tmp/a", mcp_servers=[server])], blast_radii=[])


def _possibly_affected(config_path: str) -> AIBOMReport:
    entry = {"id": "CVE-2026-1", "verdict": "possibly_affected", "reason": "no_distro_record", "detail": "verify"}
    pkg = Package(name="php8.2-cli", version="8.2.1", ecosystem="deb", purl="pkg:deb/debian/php8.2-cli@8.2.1")
    pkg.possibly_affected = [entry]
    server = MCPServer(name="os", command="", packages=[pkg])
    return AIBOMReport(agents=[Agent(name="a", agent_type="cli", config_path=config_path, mcp_servers=[server])], blast_radii=[])


def _no_source_finding(asset_type: str = "agent", name: str = "project:head") -> AIBOMReport:
    finding = Finding(
        finding_type=FindingType.COMBINATION,
        source=FindingSource.GRAPH_ANALYSIS,
        asset=Asset(name=name, asset_type=asset_type),
        severity="high",
        title=f"AI agent can reach a credential: {name} → BRIDGE_API_KEY",
        evidence={"rule_id": "AGENT_REACHES_PRIVILEGED"},
    )
    return AIBOMReport(findings=[finding])


REPORTS = {
    "every_family": _multi_finding_report,
    "exposure_chain": _full_chain_report,
    "self_scan": lambda: _vulnerable_blast("self-scan://agent-bom"),
    "no_source_package": lambda: _vulnerable_blast("agent-config.json"),
    "docker_image": lambda: _vulnerable_blast("docker://nginx:1.25"),
    "oci_tarball": lambda: _vulnerable_blast("oci-tar:///home/runner/work/app image.tar"),
    "malicious_package": _malicious_without_a_file,
    "possibly_affected": lambda: _possibly_affected("/tmp/a"),
    "possibly_affected_image": lambda: _possibly_affected("docker://nginx:1.25"),
    "no_source_finding": _no_source_finding,
}


@pytest.mark.parametrize("name", sorted(REPORTS))
def test_every_result_source_meets_the_github_location_invariant(name: str) -> None:
    document = to_sarif(REPORTS[name]())
    assert document["runs"][0]["results"], name
    assert checker.location_violations(document) == []
    schema = json.loads((ROOT / "tests/fixtures/sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
    Draft7Validator(schema).validate(document)


def test_rich_golden_meets_the_invariant() -> None:
    document = json.loads((ROOT / "tests/fixtures/output_render/rich.sarif.json").read_text(encoding="utf-8"))
    assert document["runs"][0]["results"]
    assert checker.location_violations(document) == []


def test_exposure_path_hops_survive_with_a_physical_location() -> None:
    result = next(r for r in to_sarif(_full_chain_report())["runs"][0]["results"] if r["ruleId"] == "GHSA-test-chain")
    primary = result["locations"][0]["physicalLocation"]
    hops = result["relatedLocations"]
    assert len(hops) >= 5
    for hop in hops:
        assert hop["physicalLocation"] == primary
        assert hop["logicalLocations"][0]["fullyQualifiedName"]
        assert hop["message"]["text"]
    assert result["properties"]["exposure_path"]["hops"]
    assert "Exposure path:" in result["message"]["text"]


def test_no_file_finding_is_anchored_honestly_and_keeps_its_logical_location() -> None:
    result = to_sarif(_no_source_finding())["runs"][0]["results"][0]
    location = result["locations"][0]
    uri = location["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.startswith("agent-bom-findings/agent/")
    assert location["logicalLocations"] == [{"name": "project:head", "kind": "agent"}]
    assert result["properties"]["no_source_file"] is True
    assert "region" not in location["physicalLocation"]  # no invented line


def test_real_files_are_not_marked_as_having_no_source_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "requirements.txt").write_text("urllib3==2.7.0\n", encoding="utf-8")
    report = _vulnerable_blast("agent-config.json")
    report.blast_radii[0].package.version_evidence = [{"type": "manifest", "source_file": str(tmp_path / "requirements.txt"), "line": 1}]
    result = to_sarif(report)["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "requirements.txt"
    assert "no_source_file" not in result["properties"]


def test_combination_finding_points_at_the_mcp_config_that_grants_the_credential(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    config = tmp_path / ".cursor" / "mcp.json"
    config.parent.mkdir()
    config.write_text("{}", encoding="utf-8")
    report = _no_source_finding()
    report.agents = [
        Agent(
            name="project:head",
            agent_type="custom",
            config_path=str(tmp_path),
            mcp_servers=[MCPServer(name="remote-bridge", command="npx", config_path=str(config))],
        )
    ]
    location = to_sarif(report)["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == ".cursor/mcp.json"


def test_prompt_finding_points_at_the_instruction_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.parsers.prompt_scanner import prompt_scan_data_to_findings

    monkeypatch.chdir(tmp_path)
    prompt = tmp_path / "i18n" / "es" / "instructions.md"
    prompt.parent.mkdir(parents=True)
    prompt.write_text("Install this\n", encoding="utf-8")
    findings = prompt_scan_data_to_findings(
        {"findings": [{"source_file": str(prompt), "category": "unsafe_instruction", "severity": "high", "title": "T", "line_number": 3}]}
    )
    result = to_sarif(AIBOMReport(findings=findings))["runs"][0]["results"][0]
    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "i18n/es/instructions.md"
    assert physical["region"]["startLine"] == 3


def test_command_string_is_never_used_as_an_artifact_path() -> None:
    report = _no_source_finding("mcp_server", "remote-bridge")
    report.findings[0].asset.location = "npx -y mcp-remote@0.1.15 https://example.com/mcp"
    document = to_sarif(report)
    assert checker.location_violations(document) == []
    assert document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith(
        "agent-bom-findings/"
    )


def test_windows_separators_never_reach_a_uri() -> None:
    from agent_bom.output.sarif_common import _sarif_location

    assert _sarif_location("k8s\\pod.yaml", 3)["physicalLocation"]["artifactLocation"]["uri"] == "k8s/pod.yaml"


def test_check_command_sarif_uses_a_relative_uri() -> None:
    from agent_bom.cli._check_support import _check_payload_to_sarif

    payload = {
        "package": "urllib3",
        "version": "1.26.4",
        "ecosystems": ["pypi"],
        "vulnerabilities": [{"id": "CVE-2026-1", "severity": "high", "summary": "s"}],
    }
    document = _check_payload_to_sarif(payload)
    assert document["runs"][0]["results"]
    assert checker.location_violations(document) == []


def test_checker_flags_the_real_rejected_shapes() -> None:
    document = {
        "runs": [
            {
                "results": [
                    {"ruleId": "A", "locations": [{"logicalLocations": [{"name": "x"}]}]},
                    {"ruleId": "B"},
                    {
                        "ruleId": "C",
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.txt"}}}],
                        "relatedLocations": [{"logicalLocations": [{"name": "y"}]}],
                    },
                    {"ruleId": "D", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "docker://nginx"}}}]},
                ]
            }
        ]
    }
    problems = checker.location_violations(document)
    assert [problem[0] for problem in problems] == ["A", "B", "C", "D"]


def test_sarif_never_supplies_the_hash_the_upload_action_computes() -> None:
    document = to_sarif(_multi_finding_report())
    assert not [r["ruleId"] for r in document["runs"][0]["results"] if "primaryLocationLineHash" in (r.get("partialFingerprints") or {})]
    assert all(r["fingerprints"]["agent-bom/v1"] for r in document["runs"][0]["results"])
