"""First-run console output: one line per repeated warning, honest labels, no unexplained sections."""

from __future__ import annotations

import json
import re
from io import StringIO
from pathlib import Path

from click.testing import CliRunner
from rich.console import Console

from agent_bom.cli import main
from agent_bom.cli.agents._report_written import announce_report_written
from agent_bom.cli.agents._warning_dedupe import dedupe_hardening_warnings
from agent_bom.finding import iac_finding_to_finding
from agent_bom.models import Agent, AgentStatus, AgentType, AIBOMReport, MCPServer, Package, TransportType
from agent_bom.output import print_compact_export_hint, print_compact_graph_findings, print_compact_summary
from agent_bom.output.console_compliance_gate import print_compact_compliance_section
from agent_bom.output.console_remediation import priority_tier
from agent_bom.output.dependency_hierarchy import dependency_count_label


def _capture(fn, *args, **kwargs) -> str:
    buf = StringIO()
    con = Console(file=buf, width=120, force_terminal=True, no_color=True)
    import agent_bom.output as out_mod

    orig = out_mod.console
    out_mod.console = con
    try:
        fn(*args, **kwargs)
    finally:
        out_mod.console = orig
    return re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())


def _agent(name: str, agent_type: AgentType = AgentType.CLAUDE_DESKTOP, packages: list[Package] | None = None) -> Agent:
    server = MCPServer(name=f"{name}-server", command="npx", args=[], transport=TransportType.STDIO, packages=packages or [])
    return Agent(name=name, agent_type=agent_type, config_path=f"/tmp/{name}", mcp_servers=[server], status=AgentStatus.CONFIGURED)


# ── D1: repeated CI-hardening warnings collapse to one line per rule ────────────


def test_hardening_warnings_collapse_per_rule_with_count():
    warnings = [
        "CI hardening in ci.yml: missing top-level permissions: policy; declare least-privilege GITHUB_TOKEN permissions",
        "CI hardening in ci.yml: unpinned action actions/checkout@v4; pin remote actions and reusable workflows to a full commit SHA",
        "CI hardening in ci.yml: unpinned action actions/setup-python@v5; pin remote actions and reusable workflows to a full commit SHA",
        "CI hardening in release.yml: unpinned action actions/cache@v4; pin remote actions and reusable workflows to a full commit SHA",
        "CI hardening in release.yml: missing top-level permissions: policy; declare least-privilege GITHUB_TOKEN permissions",
        "Not a hardening warning at all",
    ]
    lines = dedupe_hardening_warnings(warnings)

    assert len(lines) == 3
    assert lines[0] == (
        "CI hardening: missing top-level permissions: policy × 2 (ci.yml, release.yml); declare least-privilege GITHUB_TOKEN permissions"
    )
    assert lines[1] == (
        "CI hardening: unpinned action × 3 (ci.yml: actions/checkout@v4, actions/setup-python@v5; release.yml: actions/cache@v4); "
        "pin remote actions and reusable workflows to a full commit SHA"
    )
    assert lines[2] == "Not a hardening warning at all"


def test_single_hardening_warning_is_left_verbatim():
    only = ["CI hardening in ci.yml: unpinned action actions/checkout@v4; pin remote actions and reusable workflows to a full commit SHA"]
    assert dedupe_hardening_warnings(only) == only


def test_compact_graph_findings_group_one_iac_rule_across_distinct_messages():
    """GHA-002 fires once per action; the console shows the rule once with a count, not one group per action."""
    common = {"rule_id": "GHA-002", "title": "Action not pinned to a commit SHA", "severity": "medium", "file_path": "ci.yml"}
    findings = [
        iac_finding_to_finding({**common, "message": "'actions/checkout@v4' resolves a mutable tag.", "line_number": 7}),
        iac_finding_to_finding({**common, "message": "'actions/setup-python@v5' resolves a mutable tag.", "line_number": 8}),
        iac_finding_to_finding({"rule_id": "GHA-004", "title": "No top-level permissions", "severity": "low", "file_path": "ci.yml"}),
    ]

    output = " ".join(_capture(print_compact_graph_findings, AIBOMReport(findings=findings)).split())

    assert "3 occurrences · 2 groups" in output
    assert output.count("GHA-002") == 1
    assert "× 2 occurrences" in output


# ── D2: a critical item never reads "P2" without saying why it is not P1 ───────


def test_priority_reason_for_a_lone_critical_explains_the_p1_bar():
    tier, reason = priority_tier({"has_kev": False, "critical_count": 1, "high_count": 0, "creds": []})
    assert tier == "P2"
    assert reason == "1 critical, not known exploited; P1 needs KEV or 3+ critical"


# ── D3: a bare repository is a project, not an agent ───────────────────────────


def test_summary_counts_a_bare_repository_as_a_project():
    report = AIBOMReport(agents=[_agent("project:repro", AgentType.CUSTOM)])

    summary = _capture(print_compact_summary, report)
    hint = _capture(print_compact_export_hint, report)

    assert "1 project ·" in summary
    assert "agents" not in summary.split("Posture")[0]
    assert "1 project ·" in hint
    assert "1 agents" not in hint


def test_discover_table_is_titled_projects_when_only_projects_were_found():
    from agent_bom.output import print_compact_agents

    only_project = _capture(print_compact_agents, AIBOMReport(agents=[_agent("project:repro", AgentType.CUSTOM)]))
    both = [_agent("cursor", AgentType.CURSOR), _agent("project:repro", AgentType.CUSTOM)]
    mixed = _capture(print_compact_agents, AIBOMReport(agents=both))

    assert "DISCOVER | Projects" in only_project
    assert "DISCOVER | Agents" in mixed


def test_summary_counts_agents_and_projects_separately():
    report = AIBOMReport(agents=[_agent("cursor", AgentType.CURSOR), _agent("project:repro", AgentType.CUSTOM)])

    hint = _capture(print_compact_export_hint, report)

    assert "1 agent · 1 project ·" in hint


def test_summary_keeps_agents_wording_when_no_project_is_present():
    report = AIBOMReport(agents=[_agent("cursor", AgentType.CURSOR), _agent("zed", AgentType.ZED)])

    assert "2 agents ·" in _capture(print_compact_export_hint, report)


# ── D4: compliance block only when asked for or when compliance evidence exists ─


def test_compliance_block_is_one_hint_line_on_a_plain_scan():
    output = _capture(print_compact_compliance_section, AIBOMReport(agents=[]), compliance_enabled=False)

    assert "action required" not in output
    assert "Not evaluated" not in output
    assert "--compliance" in output
    assert len([line for line in output.splitlines() if line.strip()]) == 1


def test_compliance_block_renders_when_the_flag_is_set():
    output = _capture(print_compact_compliance_section, AIBOMReport(agents=[]), compliance_enabled=True)

    assert "action required" in output
    assert "No framework is reported as compliant" in output


def test_compliance_block_renders_when_a_benchmark_was_evaluated():
    report = AIBOMReport(agents=[], cis_benchmark_data={"account_id": "123456789012", "checks": [{"check_id": "1.1", "status": "FAIL"}]})

    output = _capture(print_compact_compliance_section, report, compliance_enabled=False)

    assert "action required" in output


# ── D5: the dependency legend reads as words, not letters ──────────────────────


def test_dependency_count_label_spells_out_the_legend():
    packages = [
        Package(name="a", version="1", ecosystem="pypi", is_direct=True),
        Package(name="b", version="1", ecosystem="pypi", is_direct=False),
        Package(name="c", version="1", ecosystem="pypi", is_direct=None),
    ]
    assert dependency_count_label(packages, compact=True) == " (1 direct/1 transitive/1 unknown)"
    assert "D/" not in dependency_count_label(packages, compact=True)


# ── D6: a file artifact is confirmed on stdout even when diagnostics go to stderr


def test_announce_report_written_goes_to_stdout(capsys):
    diagnostics = StringIO()
    con = Console(file=diagnostics, force_terminal=False)

    announce_report_written(con, "JSON report", Path("agent-bom-report.json"), quiet=False)

    assert "JSON report written to agent-bom-report.json" in capsys.readouterr().out
    assert diagnostics.getvalue() == ""


def test_announce_report_written_respects_quiet(capsys):
    announce_report_written(Console(file=StringIO()), "JSON report", Path("x.json"), quiet=True)
    assert capsys.readouterr().out == ""


def test_profile_redirected_scan_confirms_the_report_path_on_stdout(tmp_path, monkeypatch):
    config_path = tmp_path / "config.toml"
    config_path.write_text('current_profile = "default"\n\n[profiles.default]\nformat = "json"\noutput = "agent-bom-report.json"\n')
    monkeypatch.setenv("AGENT_BOM_CONFIG", str(config_path))
    monkeypatch.delenv("AGENT_BOM_PROFILE", raising=False)
    project = tmp_path / "myproject"
    project.mkdir()
    (project / "requirements.txt").write_text("flask==2.0.0\n")
    monkeypatch.chdir(project)

    result = CliRunner().invoke(main, ["scan", ".", "--no-scan", "--no-auto-update-db", "--offline"], catch_exceptions=False)

    assert result.exit_code == 0, result.output
    assert "JSON report written to" in result.stdout
    assert "agent-bom-report.json" in result.stdout
    assert json.loads((project / "agent-bom-report.json").read_text())["agents"]
