"""First-run console wording explains counts and staleness instead of leaving numbers bare."""

from __future__ import annotations

import io
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from rich.console import Console

from agent_bom.cli import main
from agent_bom.scanners import local_data_freshness, package_scan
from agent_bom.vuln_freshness import VulnDataFreshness


def _stale(mode: str) -> VulnDataFreshness:
    return VulnDataFreshness(mode=mode, age_hours=75 * 24, last_updated="2026-08-01T00:00:00+00:00", stale=True, sources=["osv"])


@pytest.mark.parametrize(("mode", "args", "expected"), [("offline", ["--offline"], "only local data"), ("local", [], "OSV live")])
def test_stale_db_warning_names_the_refresh_command_and_consequence(monkeypatch, tmp_path, mode, args, expected) -> None:
    monkeypatch.setattr("agent_bom.vuln_freshness.compute_freshness", lambda **kwargs: _stale(mode))

    async def clean_lookup(*_a, **_k):
        return 0

    monkeypatch.setattr("agent_bom.scanners.scan_packages", clean_lookup)
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--no-discover", "--no-auto-update-db", "-f", "console", *args], catch_exceptions=False
    )
    out = " ".join(result.output.split())
    assert "Vulnerability DB is stale (75 days old" in out
    assert "Refresh it: agent-bom db update" in out
    assert expected in out


def test_local_hits_line_reports_matches_not_confirmed_vulnerabilities(monkeypatch) -> None:
    monkeypatch.setattr(local_data_freshness, "freshness_snapshot", lambda offline: _stale("offline"))
    line = local_data_freshness.local_hits_line(12, offline=True, prefer_local_db=False, demo=False)
    assert "12 advisory matches" in line and "vulnerabilities found" not in line
    assert "75 days old" in line


def _br(vuln_id: str, pkg: str) -> SimpleNamespace:
    return SimpleNamespace(vulnerability=SimpleNamespace(id=vuln_id), package=SimpleNamespace(ecosystem="pypi", name=pkg, version="1"))


def test_vulnerability_summary_counts_findings_packages_and_advisories(monkeypatch) -> None:
    out = io.StringIO()
    monkeypatch.setattr(package_scan, "console", Console(file=out, width=200))
    radii = [_br("CVE-1", "a"), _br("CVE-2", "a"), _br("CVE-1", "b")]
    package_scan._print_vulnerability_summary(24, 3, blast_radii=radii)
    text = out.getvalue()
    assert "Found 3 known vulnerabilities in 2 packages (2 distinct advisories)" in text
    assert "24" not in text


def test_unconfirmed_local_matches_are_explained() -> None:
    from agent_bom.scanners.clean_verdict import unconfirmed_matches_line

    text = " ".join((unconfirmed_matches_line(12) or "").split())
    assert "12 local advisory matches could not be confirmed" in text and "possibly affected" in text
    assert unconfirmed_matches_line(0) is None


def test_ungraded_posture_states_why_instead_of_zero_score() -> None:
    from agent_bom.output.compact import _posture_grade_badge, _posture_headline
    from agent_bom.output.compact_rows import posture_grade_line

    line = posture_grade_line(_posture_grade_badge, _posture_headline, "N/A", 0.0, "scan coverage incomplete")
    assert "0/100" not in line and "not graded" in line and "scan coverage incomplete" in line
    assert "69/100" in posture_grade_line(_posture_grade_badge, _posture_headline, "D", 69.0, "Weak best-practice/config posture")


def test_console_groups_mcp_schema_rules_per_server_but_keeps_other_rows() -> None:
    from agent_bom.finding import Asset, Finding, FindingSource, FindingType
    from agent_bom.output.compact_rows import console_group_key as _console_group_key

    def schema(tool: str, server: str) -> Finding:
        return Finding(
            finding_type=FindingType.PROMPT_SECURITY,
            source=FindingSource.MCP_SCAN,
            asset=Asset(name=f"{tool} on {server}", asset_type="mcp_tool", identifier=f"{server}:{tool}"),
            severity="low",
            title=f"MCP schema risk on {tool}",
            evidence={"category": "schema_risk", "server_name": server, "rule_id": "MCP-T001", "property_name": tool},
        )

    keys = {_console_group_key(schema(f"browser_{i}", "playwright")) for i in range(21)}
    assert len(keys) == 1
    assert _console_group_key(schema("x", "other")) not in keys
    plain = Finding(
        finding_type=FindingType.PROMPT_SECURITY,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="srv", asset_type="mcp_server", identifier="srv"),
        severity="high",
        title="MCP over permission on srv",
        evidence={"category": "over_permission"},
    )
    assert _console_group_key(plain) is None


def test_cyclonedx_named_output_is_accepted_with_a_note(capsys) -> None:
    from agent_bom.cli.agents._output import _resolve_output_path

    assert _resolve_output_path("x.cyclonedx", "cyclonedx") == "x.cyclonedx.json"
    assert "short form" in capsys.readouterr().err
    assert _resolve_output_path("x.cyclonedx.json", "cyclonedx") == "x.cyclonedx.json"


def test_dev_dependency_scope_is_recognised_for_console_labels() -> None:
    from agent_bom.finding import Asset, Finding, FindingSource, FindingType
    from agent_bom.output.finding_views import is_dev_dependency

    def cve(scope: str) -> Finding:
        return Finding(
            finding_type=FindingType.CVE,
            source=FindingSource.MCP_SCAN,
            asset=Asset(name="pytest", asset_type="package", identifier="pypi:pytest@7.0.0"),
            severity="medium",
            title="CVE",
            evidence={"package_dependency_scope": scope},
        )

    assert is_dev_dependency(cve("dev"))
    assert not is_dev_dependency(cve("runtime")) and not is_dev_dependency(cve("unknown"))
