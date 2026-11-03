"""Next-step hints and the per-target "since last scan" header stay human-only and opt-out."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from rich.console import Console

from agent_bom.cli import scan_hints
from agent_bom.storage import last_scan_summary as memory

_CI_VARS = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "CIRCLECI", "TRAVIS", "TF_BUILD", "BITBUCKET_PIPELINE_UUID")


@pytest.fixture(autouse=True)
def _local_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state = tmp_path / "state"
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(state))
    for var in (*_CI_VARS, scan_hints.HINTS_OPT_OUT_ENV, memory.OPT_OUT_ENV):
        monkeypatch.delenv(var, raising=False)
    return state


def _tty() -> Console:
    return Console(file=io.StringIO(), force_terminal=True, width=200)


def _report(**overrides: object) -> SimpleNamespace:
    base = {"blast_radii": [], "total_vulnerabilities": 0, "total_servers": 0, "total_agents": 0}
    base.update(overrides)
    return SimpleNamespace(**base)


def test_hints_only_for_interactive_non_ci_non_quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    assert scan_hints.hints_enabled(_tty(), quiet=False)
    assert not scan_hints.hints_enabled(_tty(), quiet=True)
    assert not scan_hints.hints_enabled(Console(file=io.StringIO(), force_terminal=False), quiet=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert not scan_hints.hints_enabled(_tty(), quiet=False)
    monkeypatch.delenv("GITHUB_ACTIONS")
    monkeypatch.setenv("CI", "1")
    assert not scan_hints.hints_enabled(_tty(), quiet=False)
    monkeypatch.delenv("CI")
    monkeypatch.setenv(scan_hints.HINTS_OPT_OUT_ENV, "1")
    assert not scan_hints.hints_enabled(_tty(), quiet=False)


def test_hints_are_contextual() -> None:
    clean = scan_hints.next_step_hints(_report())
    assert clean == []
    findings = " ".join(scan_hints.next_step_hints(_report(total_vulnerabilities=3)))
    assert "koda-ai-studio/agent-bom@v0" in findings and "claude mcp add" not in findings
    mcp = " ".join(scan_hints.next_step_hints(_report(total_servers=2, total_agents=1), first_scan_of_target=True))
    assert "claude mcp add agent-bom -- uvx agent-bom mcp server" in mcp
    assert "agent-bom watch" in mcp and "agent-bom-guard@agent-bom" in mcp
    assert "Rerun" in mcp and "agent-bom@v0" not in mcp


def test_star_line_shown_once_per_machine_and_only_after_success(_local_state: Path) -> None:
    assert scan_hints.star_hint_once(scan_succeeded=False) is None
    assert not (_local_state / "hints" / "star-shown").exists()
    first = scan_hints.star_hint_once(scan_succeeded=True)
    assert first and "github.com/koda-ai-studio/agent-bom" in first and scan_hints.HINTS_OPT_OUT_ENV in first
    assert (_local_state / "hints" / "star-shown").exists()
    assert scan_hints.star_hint_once(scan_succeeded=True) is None


def test_star_line_withheld_when_marker_cannot_be_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    blocker = tmp_path / "file-not-dir"
    blocker.write_text("x")
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(blocker))
    assert scan_hints.star_hint_once(scan_succeeded=True) is None


def _report_json(vulns: list[tuple[str, str]], servers: list[str], *, outcome: str = "complete") -> dict:
    return {
        "generated_at": "2026-11-01T10:00:00+00:00",
        "scan_run": {"outcome": outcome},
        "blast_radius": [{"vulnerability_id": v, "package": p, "ecosystem": "pypi"} for v, p in vulns],
        "inventory_snapshot": {"servers": [{"id": f"srv:{s}", "name": s} for s in servers], "tools": []},
    }


def test_summary_stores_identities_only_and_is_bounded(_local_state: Path) -> None:
    report = _report_json([("CVE-1", "requests@2.19.0")], ["pw"])
    report["agents"] = [{"name": "x", "config_path": "/home/me/.claude.json", "env": {"API_KEY": "sk-not-a-real-key"}}]
    summary = memory.build_summary(report, outcome="complete")
    memory.save_summary("k" * 32, summary)
    written = (_local_state / "last-scan" / f"{'k' * 32}.json").read_text()
    assert "config_path" not in written and "API_KEY" not in written and "/home/me" not in written
    assert oct(os.stat(_local_state / "last-scan" / f"{'k' * 32}.json").st_mode & 0o777) == "0o600"
    for i in range(memory.MAX_TARGETS + 5):
        memory.save_summary(f"{i:032d}", summary)
    assert len(list((_local_state / "last-scan").glob("*.json"))) == memory.MAX_TARGETS


def test_delta_uses_the_shared_diff_judgement() -> None:
    previous = memory.build_summary(_report_json([("CVE-1", "requests@2.19.0"), ("CVE-2", "jinja2@2.10")], ["pw"]), outcome="complete")
    current = memory.build_summary(
        _report_json([("CVE-1", "requests@2.20.0"), ("CVE-3", "pillow@9.0.0")], ["pw", "fs"]), outcome="complete"
    )
    change = memory.compare(previous, current)
    assert (change.new_findings, change.resolved_findings, change.new_servers, change.partial) == (1, 1, 1, False)
    line = memory.delta_line(change)
    assert "Since last scan" in line and "1 new vulnerability" in line and "1 resolved" in line and "1 new MCP server" in line
    same = memory.compare(current, current)
    assert same.unchanged and "no new or resolved" in memory.delta_line(same)
    partial = memory.compare(previous, memory.build_summary(_report_json([], []), outcome="partial"))
    assert partial.partial and "partial scan" in memory.delta_line(partial)


def test_target_key_does_not_store_inputs_and_distinguishes_targets() -> None:
    a = memory.target_key({"path": "/repo/a", "no_discover": True})
    b = memory.target_key({"path": "/repo/b", "no_discover": True})
    assert a != b and "/repo" not in a and len(a) == 32
    assert a == memory.target_key({"no_discover": True, "path": "/repo/a", "images": ()})


def _scan(project: Path, *args: str, env: dict[str, str] | None = None) -> str:
    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["scan", str(project), "--no-discover", "--no-auto-update-db", "--allow-stale-db", "--exit-zero", *args],
        env=env or {},
        catch_exceptions=False,
    )
    return result.output


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    async def clean_lookup(*_args: object, **_kwargs: object) -> int:
        return 0

    monkeypatch.setattr("agent_bom.scanners.scan_packages", clean_lookup)
    root = tmp_path / "proj"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.33.0\n")
    return root


def test_rescan_prints_delta_header_in_console_only(project: Path, _local_state: Path) -> None:
    first = _scan(project, "-f", "console")
    assert "Since last scan" not in first
    assert len(list((_local_state / "last-scan").glob("*.json"))) == 1
    second = _scan(project, "-f", "console")
    assert "Since last scan" in second
    as_json = _scan(project, "-f", "json")
    payload = json.loads(as_json[as_json.index("{") :])
    assert "Since last scan" not in as_json and "blast_radius" in payload


def test_scan_memory_opt_out_and_ci_store_nothing(project: Path, _local_state: Path) -> None:
    _scan(project, "-f", "console", env={memory.OPT_OUT_ENV: "1"})
    _scan(project, "-f", "console", env={"CI": "true"})
    assert not (_local_state / "last-scan").exists()


def test_non_tty_console_scan_has_no_hints_or_star(project: Path, _local_state: Path) -> None:
    out = _scan(project, "-f", "console")
    assert "a GitHub star" not in out and "claude mcp add" not in out
    assert not (_local_state / "hints" / "star-shown").exists()


def test_html_report_footer_carries_static_next_steps() -> None:
    from agent_bom.models import AIBOMReport
    from agent_bom.output.html import to_html
    from agent_bom.output.next_steps import next_steps_html

    page = to_html(AIBOMReport(agents=[]), [])
    assert '<section class="next-steps"' in page and "Star agent-bom on GitHub" in page
    assert "koda-ai-studio/agent-bom@v0" not in page.split('<section class="next-steps"')[1].split("</section>")[0]
    block = next_steps_html(_report(total_vulnerabilities=2, total_servers=1))
    assert "uses: koda-ai-studio/agent-bom@v0" in block and "claude mcp add agent-bom" in block
    assert "<script" not in block and "img" not in block


def test_print_hints_on_a_terminal_shows_star_once(_local_state: Path) -> None:
    con = _tty()
    scan_hints.print_hints(con, _report(total_servers=1), target=".", first_scan_of_target=True, scan_succeeded=True)
    scan_hints.print_hints(con, _report(total_servers=1), target=".", first_scan_of_target=False, scan_succeeded=True)
    text = con.file.getvalue()
    assert text.count("a GitHub star") == 1
    assert text.count("claude mcp add agent-bom") == 2
