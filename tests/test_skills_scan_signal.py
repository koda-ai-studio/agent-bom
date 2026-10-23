"""`agent-bom skills scan` reports what it found, and only that."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main

ROOT = Path(__file__).resolve().parents[1]
PLUGINS = [ROOT / "integrations" / "claude-code", ROOT / "integrations" / "codex"]

CLAWHUB_SKILL = """---
name: fetcher
description: Fetch pages for the user.
metadata:
  openclaw:
    requires:
      bins: [curl]
---

Fetch the page the user names.
"""


def _scan(target: Path, *extra: str):
    return CliRunner().invoke(main, ["skills", "scan", str(target), *extra])


@pytest.mark.parametrize("plugin", PLUGINS, ids=lambda p: p.name)
def test_our_plugin_skills_scan_clean(plugin):
    result = _scan(plugin, "--format", "json")
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    summary = data["summary"]
    assert summary["files_scanned"] >= 10 and summary["findings"] == 0
    assert summary["clean_files"] == summary["files_scanned"]
    for report in data["files"]:
        assert report["status"] == "clean", report["path"]
        assert report["trust"]["review_verdict"] == "trusted", (report["path"], report["trust"]["review_reasons"])
        assert report["trust"]["publisher_guidance"] == [], report["path"]


def test_clean_console_output_says_so_and_names_each_skill(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # outside the repo, so paths cannot be shown relative to cwd
    result = CliRunner().invoke(main, ["skills", "scan", str(PLUGINS[0])], terminal_width=200)
    assert result.exit_code == 0, result.output
    out = result.output
    assert "Recommended next steps" not in out
    assert "pending" not in out
    assert "no findings" in out.lower()
    for skill in ("scan", "inventory", "audit-skills"):
        assert f"{skill}/SKILL.md" in out


def test_clawhub_manifest_gaps_are_still_reported(tmp_path):
    skill = tmp_path / "fetcher" / "SKILL.md"
    skill.parent.mkdir()
    skill.write_text(CLAWHUB_SKILL)
    data = json.loads(_scan(tmp_path, "--format", "json").stdout)
    trust = data["files"][0]["trust"]
    scope = next(c for c in trust["categories"] if c["key"] == "instruction_scope")
    assert scope["level"] == "warn"
    assert "Add file_reads list to enumerate all config paths accessed" in trust["publisher_guidance"]


def test_pending_status_is_explained(tmp_path, monkeypatch):
    skill = tmp_path / "fetcher" / "SKILL.md"
    skill.parent.mkdir()
    skill.write_text(CLAWHUB_SKILL)
    monkeypatch.chdir(tmp_path)
    out = CliRunner().invoke(main, ["skills", "scan", str(tmp_path)], terminal_width=200).output
    assert "pending" in out
    assert "pending:" in out and "file_reads" in out
