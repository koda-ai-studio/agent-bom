"""A project manifest directory that an MCP server already binds is counted once in report totals.

``agent-bom scan DIR`` on the first-run sample reported 10 packages for 5
unique and 88 vulnerability occurrences for 44: each ``services/*`` manifest
group re-bound the packages its MCP server had already extracted from the
same directory. Both bindings stay in the report as evidence; totals count the
MCP server's binding only.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.api.models import PushPayload
from agent_bom.api.push_evidence import normalize_pushed_report
from agent_bom.cli import main
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package, ServerSurface, Severity, Vulnerability
from agent_bom.output.vulnerability_counts import vulnerability_counts
from agent_bom.parsers.package_bindings import mark_manifest_bindings
from agent_bom.samples import write_first_run_sample


@pytest.fixture
def sample(tmp_path: Path, monkeypatch) -> Path:
    target = tmp_path / "sample1"
    write_first_run_sample(target)
    monkeypatch.chdir(target)
    return target


def _scan(sample: Path, fmt: str) -> Path:
    out = sample.parent / f"out.{fmt}.json"
    result = CliRunner().invoke(main, ["scan", ".", "--offline", "--no-scan", "-f", fmt, "-q", "-o", str(out)])
    assert out.is_file(), result.output
    return out


def test_sample_scan_counts_each_package_binding_once(sample: Path) -> None:
    report = json.loads(_scan(sample, "json").read_text())
    summary = report["summary"]
    assert summary["unique_packages"] == 5
    assert summary["total_packages"] == 5
    servers = {server["name"]: server for agent in report["agents"] for server in agent["mcp_servers"]}
    assert servers["services/research-mcp"]["package_binding_of"] == servers["research-filesystem"]["canonical_id"]
    assert servers["services/browser-helper"]["package_binding_of"] == servers["browser-helper"]["canonical_id"]
    assert len(servers["services/research-mcp"]["packages"]) == 3
    assert "package_binding_of" not in servers["research-filesystem"]
    pushed = normalize_pushed_report(PushPayload(**report), fallback_scan_id="r")
    assert pushed["summary"]["total_packages"] == 5


def test_console_package_line_counts_each_binding_once(sample: Path) -> None:
    out = sample.parent / "console.json"
    result = CliRunner().invoke(main, ["scan", ".", "--offline", "--no-scan", "-f", "json", "-o", str(out)])
    assert "5 packages (3 pypi, 2 npm)" in result.output


def test_sample_spdx_summary_uses_the_deduplicated_total(sample: Path) -> None:
    document = json.loads(_scan(sample, "spdx").read_text())
    assert "5 package(s)" in json.dumps(document)
    assert "10 package(s)" not in json.dumps(document)


def _vulnerable(name: str) -> Package:
    package = Package(name=name, version="1.0", ecosystem="pypi")
    package.vulnerabilities = [Vulnerability(id=f"CVE-2026-{index:05d}", summary="x", severity=Severity.HIGH) for index in range(2)]
    return package


def test_occurrences_skip_the_duplicate_manifest_binding(tmp_path: Path) -> None:
    service = tmp_path / "svc"
    service.mkdir()
    (service / "server.py").write_text("")
    mcp = MCPServer(name="svc", command="python", args=[str(service / "server.py")], packages=[_vulnerable("flask")])
    manifest = MCPServer(name="svc", command="project", args=[str(service)], surface=ServerSurface.OTHER, packages=[_vulnerable("flask")])
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    unrelated = MCPServer(
        name="other", command="project", args=[str(other_dir)], surface=ServerSurface.OTHER, packages=[_vulnerable("flask")]
    )
    agents = [
        Agent(name="cursor", agent_type=AgentType.CURSOR, config_path="x", mcp_servers=[mcp]),
        Agent(name="project:p", agent_type=AgentType.CUSTOM, config_path="p", source="project", mcp_servers=[manifest, unrelated]),
    ]
    assert mark_manifest_bindings(agents) == 1
    assert manifest.package_binding_of == mcp.canonical_id
    assert unrelated.package_binding_of is None
    report = AIBOMReport(agents=agents)
    assert report.total_packages == 2
    counts = vulnerability_counts(report)
    assert counts["vulnerability_occurrences"] == 4
    assert counts["total_vulnerabilities"] == 2
    assert report.total_vulnerabilities == 4


def test_manifest_with_packages_the_server_lacks_is_not_a_duplicate(tmp_path: Path) -> None:
    service = tmp_path / "svc"
    service.mkdir()
    (service / "server.py").write_text("")
    mcp = MCPServer(name="svc", command="python", args=[str(service / "server.py")], packages=[_vulnerable("flask")])
    manifest = MCPServer(
        name="svc",
        command="project",
        args=[str(service)],
        surface=ServerSurface.OTHER,
        packages=[_vulnerable("flask"), _vulnerable("jinja2")],
    )
    agents = [Agent(name="project:p", agent_type=AgentType.CUSTOM, config_path="p", source="project", mcp_servers=[mcp, manifest])]
    assert mark_manifest_bindings(agents) == 0
    assert AIBOMReport(agents=agents).total_packages == 3
