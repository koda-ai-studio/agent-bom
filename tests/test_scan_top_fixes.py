"""End-of-scan top fixes for scans whose report is written to a file."""

from __future__ import annotations

from datetime import datetime, timezone

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli.agents.scan_pipeline.top_fixes import top_fix_lines
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import AIBOMReport


def _finding(index: int, name: str, severity: str, fixed: str | None, *, malicious: bool = False) -> Finding:
    return Finding(
        id=f"finding-{index}",
        finding_type=FindingType.CVE,
        source=FindingSource.SBOM,
        asset=Asset(name=name, asset_type="package"),
        severity=severity,
        title=f"CVE-2026-{index:04} in {name}",
        cve_id=f"CVE-2026-{index:04}",
        fixed_version=fixed,
        risk_score=8.0 - index,
        evidence={"package_name": name, "package_version": "1.0.0", "ecosystem": "pypi", "package_is_malicious": malicious},
    )


def _report(*findings: Finding) -> AIBOMReport:
    report = AIBOMReport(generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc), tool_version="0.0.0-test")
    report.findings.extend(findings)
    return report


def test_top_fixes_lead_with_removals_then_upgrades_and_stop_at_three() -> None:
    report = _report(
        _finding(0, "alpha", "critical", "2.0.0"),
        _finding(1, "alpha", "high", "2.1.0"),
        _finding(2, "bravo", "high", "3.0.0"),
        _finding(3, "charlie", "medium", "1.5.0"),
        _finding(4, "delta", "low", "1.2.0"),
        _finding(5, "unfixed", "critical", None),
        _finding(6, "evil-pkg", "critical", "9.9.9", malicious=True),
    )

    lines = top_fix_lines(report)
    text = "\n".join(lines)

    assert lines[0] == "Top fixes (3 of 5 actionable):"
    numbered = [line for line in lines if line[:3] in {"1. ", "2. ", "3. "}]
    assert len(numbered) == 3
    assert numbered[0].startswith("1. Remove evil-pkg")
    assert numbered[1].startswith("2. Upgrade alpha 1.0.0 → 2.1.0") and "2 advisories" in numbered[1]
    assert "pip install" in text
    assert "4." not in text
    assert "unfixed" not in text, "a package with no fix is not a top fix"


def test_top_fixes_are_empty_without_an_actionable_fix() -> None:
    assert top_fix_lines(_report()) == []
    assert top_fix_lines(_report(_finding(0, "unfixed", "critical", None))) == []


def test_file_output_scan_ends_with_top_fixes_and_a_next_step(tmp_path) -> None:
    out = tmp_path / "agent-bom-report.html"
    result = CliRunner().invoke(main, ["scan", "--demo", "--offline", "-f", "html", "-o", str(out)])

    assert out.is_file()
    written = result.output.index("HTML report written")
    fixes = result.output.index("Top fixes (")
    assert written < fixes
    tail = result.output[fixes:]
    assert "1. " in tail
    assert "Next:" in tail and "--remediate remediation.md" in tail
    assert "scan --demo --offline --remediate remediation.md" in " ".join(tail.split())


def test_console_and_quiet_scans_do_not_repeat_top_fixes(tmp_path) -> None:
    runner = CliRunner()
    console = runner.invoke(main, ["scan", "--demo", "--offline"])
    quiet = runner.invoke(main, ["scan", "--demo", "--offline", "-q", "-f", "json", "-o", str(tmp_path / "r.json")])

    assert "Top fixes (" not in console.output
    assert "Top fixes (" not in quiet.output


def test_json_written_to_stdout_stays_parseable() -> None:
    import json

    result = CliRunner().invoke(main, ["scan", "--demo", "--offline", "-f", "json"])

    payload = json.loads(result.output[result.output.index("{") :])
    assert payload
    assert "Top fixes (" not in result.output
