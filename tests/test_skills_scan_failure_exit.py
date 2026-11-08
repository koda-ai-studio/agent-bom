"""A skill scan that could not read a file never reports it clean."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom import skills_service
from agent_bom.cli._skills_group import skills_group


@pytest.fixture
def broken_scan(monkeypatch: pytest.MonkeyPatch):
    async def fail(*_args, **_kwargs):
        raise ValueError("parser failure")

    monkeypatch.setattr(skills_service, "_build_skill_report_async", fail)


def _skill(tmp_path: Path) -> Path:
    skill = tmp_path / "SKILL.md"
    skill.write_text("---\nname: h\ndescription: d\n---\n\n# Hello\n", encoding="utf-8")
    return skill


@pytest.mark.parametrize("flags", [[], ["--ci"]], ids=["default", "ci"])
def test_a_failed_scan_exits_as_incomplete(tmp_path: Path, broken_scan, flags: list[str]) -> None:
    result = CliRunner().invoke(skills_group, ["scan", str(_skill(tmp_path)), "-f", "json", *flags], env={"CI": ""})
    assert result.exit_code == 2, result.output


def test_a_failed_scan_is_not_reported_benign(tmp_path: Path, broken_scan) -> None:
    report = skills_service.scan_skill_targets([_skill(tmp_path)])
    payload = report.to_dict()
    assert payload["summary"]["failed_files"] == 1
    assert payload["files"][0]["scan_failed"] is True
    assert payload["files"][0]["trust"]["verdict"] != "benign"


def test_a_completed_scan_keeps_its_exit_and_marks_nothing_failed(tmp_path: Path) -> None:
    result = CliRunner().invoke(skills_group, ["scan", str(_skill(tmp_path)), "-f", "json"], env={"CI": ""})
    assert result.exit_code == 0, result.output
    report = skills_service.scan_skill_targets([_skill(tmp_path)]).to_dict()
    assert report["summary"]["failed_files"] == 0
    assert "scan_failed" not in report["files"][0]
