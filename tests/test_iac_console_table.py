"""`agent-bom iac --format console` lists the findings, not just a count."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner
from rich.console import Console

from agent_bom.cli import main
from agent_bom.iac.models import IaCFinding
from agent_bom.output.console_iac import iac_severity_summary, print_iac_findings_table

_FIXTURES = Path(__file__).parent / "fixtures" / "iac_golden"


def _finding(rule_id: str, severity: str, file_path: str, line: int, title: str) -> IaCFinding:
    return IaCFinding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        message="",
        file_path=file_path,
        line_number=line,
        category="kubernetes",
    )


_SAMPLE = [
    _finding("K8S-010", "low", "deploy.yaml", 40, "No resource limits"),
    _finding("K8S-001", "critical", "deploy.yaml", 12, "Privileged container"),
    _finding("DOCKER-010", "high", "Dockerfile", 3, "Runs as root"),
    _finding("TF-AWS-004", "medium", "infra/s3.tf", 7, "S3 bucket without versioning [bold]x[/bold]"),
    _finding("K8S-002", "critical", "api.yaml", 0, "Host network enabled"),
]


def _render(findings, **kwargs) -> str:
    con = Console(record=True, width=80, color_system=None, force_terminal=False)
    print_iac_findings_table(con, findings, **kwargs)
    return con.export_text()


def test_table_is_severity_sorted_with_rule_location_and_title():
    text = _render(_SAMPLE)
    assert text == (
        "\n"
        "  Sev     Rule        Location                Title                             \n"
        "   CRIT   K8S-002     api.yaml                Host network enabled              \n"
        "   CRIT   K8S-001     deploy.yaml:12          Privileged container              \n"
        "   HIGH   DOCKER-010  Dockerfile:3            Runs as root                      \n"
        "   MED    TF-AWS-004  infra/s3.tf:7           S3 bucket without versioning      \n"
        "                                              [bold]x[/bold]                    \n"
        "   LOW    K8S-010     deploy.yaml:40          No resource limits                \n"
    )


def test_table_caps_rows_with_honest_remainder_and_format_hint():
    findings = [_finding(f"K8S-{i:03d}", "medium", "deploy.yaml", i, f"Rule {i}") for i in range(1, 31)]
    text = _render(findings, limit=25)
    assert "K8S-025" in text and "K8S-026" not in text
    assert "+5 more finding(s)" in text
    assert "-f json" in text and "-f sarif" in text
    assert all(len(line) <= 80 for line in text.splitlines())


def test_table_without_limit_shows_every_finding():
    findings = [_finding(f"K8S-{i:03d}", "low", "deploy.yaml", i, f"Rule {i}") for i in range(1, 31)]
    text = _render(findings, limit=None)
    assert "K8S-030" in text
    assert "more finding" not in text


def test_table_prints_nothing_for_no_findings():
    assert _render([]) == ""


def test_long_paths_wrap_inside_80_columns():
    long_path = "services/payments/" + "nested/" * 8 + "deployment.yaml"
    text = _render([_finding("K8S-001", "critical", long_path, 120, "Privileged container")])
    assert all(len(line) <= 80 for line in text.splitlines())
    assert "deployment.yaml:120" in text.replace("\n", "").replace(" ", "")


def test_severity_summary_counts_every_band():
    assert iac_severity_summary(_SAMPLE, markup=False) == "2 critical · 1 high · 1 medium · 1 low"
    assert iac_severity_summary([_SAMPLE[0]], markup=False) == "1 low"


def test_iac_command_console_lists_findings_from_fixture():
    result = CliRunner().invoke(main, ["iac", str(_FIXTURES / "kubernetes"), "--format", "console"], terminal_width=80)
    output = result.output
    assert "Sev" in output and "Rule" in output and "Location" in output
    assert "K8S-001" in output
    assert "harvested_041a6158d83a0b84.yaml:12" in output
    assert "27 critical · 43 high · 98 medium · 107 low" in output
    assert "+250 more finding(s)" in output
    rows = [line.split() for line in output.splitlines() if line.strip().startswith(("CRIT ", "HIGH ", "MED ", "LOW "))]
    assert len(rows) == 25
    assert all(row[0] == "CRIT" for row in rows)  # 27 critical findings fill the first 25 rows


def test_iac_command_quiet_console_keeps_table_out():
    result = CliRunner().invoke(main, ["iac", str(_FIXTURES / "kubernetes"), "--format", "console", "--quiet"], terminal_width=80)
    assert "more finding(s)" not in result.output
