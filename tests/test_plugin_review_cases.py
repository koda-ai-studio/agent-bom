"""The directory review cases: real prompts, exact counts, synthetic data, runnable fixture."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from agent_bom.mcp_tools.profiles import get_profile

ROOT = Path(__file__).resolve().parents[1]
CLAUDE_CASES = ROOT / "integrations" / "claude-code" / "evals" / "review-cases.json"
GUARD_CASES = ROOT / "integrations" / "agent-bom-guard" / "review-cases.json"
OPENAI_CASES = ROOT / "integrations" / "codex" / "review-cases.json"
ALL_CASES = (CLAUDE_CASES, GUARD_CASES, OPENAI_CASES)
DOC = ROOT / "docs" / "PLUGIN_REVIEW_CASES.md"
TOOL = re.compile(r"mcp__plugin_agent-bom_(agent-bom(?:-audit)?)__(\w+)")
PROFILES = {"agent-bom": "scan", "agent-bom-audit": "audit"}


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", ALL_CASES, ids=lambda p: p.parent.name)
def test_each_directory_has_five_positive_and_three_negative_cases(path: Path) -> None:
    data = _load(path)
    assert len(data["positive"]) == 5
    assert len(data["negative"]) == 3
    ids = [case["id"] for case in data["positive"] + data["negative"]]
    assert len(set(ids)) == len(ids)


@pytest.mark.parametrize("path", ALL_CASES, ids=lambda p: p.parent.name)
def test_cases_carry_what_a_reviewer_needs(path: Path) -> None:
    data = _load(path)
    for case in data["positive"]:
        for key in ("scenario", "prompt", "expected_tools", "expected_result", "last_run"):
            assert case.get(key), (case["id"], key)
    for case in data["negative"]:
        for key in ("scenario", "prompt", "why_not", "must_not_call", "expected_result"):
            assert case.get(key), (case["id"], key)


@pytest.mark.parametrize("path", ALL_CASES, ids=lambda p: p.parent.name)
def test_negative_cases_record_how_far_they_were_verified(path: Path) -> None:
    for case in _load(path)["negative"]:
        assert case.get("last_run"), case["id"]


def test_claude_cases_call_tools_the_plugin_serves() -> None:
    data = _load(CLAUDE_CASES)
    for case in data["positive"]:
        for tool in case["expected_tools"]:
            match = TOOL.fullmatch(tool)
            if match:
                assert match.group(2) in get_profile(PROFILES[match.group(1)]).tools, tool


def test_claude_cases_point_at_runnable_evals() -> None:
    data = _load(CLAUDE_CASES)
    for case in data["positive"] + data["negative"]:
        case_dir = CLAUDE_CASES.parent / case["eval_case"]
        assert (case_dir / "prompt.md").is_file(), case["id"]
        assert list((case_dir / "graders").glob("*.md")), case["id"]


def test_openai_cases_run_only_the_shipped_cli_commands() -> None:
    allowed = re.compile(r"^(mcp inventory|mcp audit|scan|check|remediate|skills scan|where|db advisory match)\b")
    for case in _load(OPENAI_CASES)["positive"]:
        for command in case["expected_tools"]:
            assert allowed.match(command), command
    for case in _load(OPENAI_CASES)["negative"]:
        assert case["must_not_call"]


@pytest.mark.parametrize("path", ALL_CASES, ids=lambda p: p.parent.name)
def test_cases_use_only_synthetic_data(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert not re.search(r"/Users/|/home/(?!dev)|[\w.+-]+@(?!example\b)[a-z0-9-]+\.(com|org|net|io)\b", text)
    assert not re.search(r"AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}", text)


def test_review_doc_lists_every_prompt_verbatim() -> None:
    doc = DOC.read_text(encoding="utf-8")
    for path in ALL_CASES:
        data = _load(path)
        for case in data["positive"] + data["negative"]:
            assert case["prompt"] in doc, case["id"]


def test_fixture_writes_the_files_the_cases_need(tmp_path: Path) -> None:
    target = tmp_path / "demo"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "plugin_review_fixture.py"), str(target)], check=True)
    config = json.loads((target / ".mcp.json").read_text())
    assert {"demo-notes", "demo-remote"} <= set(config["mcpServers"])
    assert (target / "requirements.txt").read_text().strip() == "idna==3.6"
    assert (target / ".claude" / "skills" / "deploy-helper" / "SKILL.md").is_file()
    assert "example.invalid" in (target / ".claude" / "skills" / "deploy-helper" / "SKILL.md").read_text()
