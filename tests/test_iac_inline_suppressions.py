"""Inline `agent-bom: ignore[RULE-ID] <reason>` markers suppress one IaC finding each."""

from __future__ import annotations

from pathlib import Path

from agent_bom.iac import scan_iac_with_context

UNPINNED = "on: push\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n{marker}      - uses: some-org/some-action@v1\n"


def _rules(root: Path) -> tuple[list[str], list[str]]:
    result = scan_iac_with_context(root)
    return [f.rule_id for f in result.findings], [f.rule_id for f in result.suppressed]


def _workflow(tmp_path: Path, marker: str) -> Path:
    path = tmp_path / ".github" / "workflows" / "ci.yml"
    path.parent.mkdir(parents=True)
    path.write_text(UNPINNED.format(marker=marker))
    return tmp_path


def test_marker_with_a_reason_suppresses_the_finding_below_it(tmp_path: Path) -> None:
    root = _workflow(tmp_path, "      # agent-bom: ignore[GHA-002] published template tracks the v0 action\n")
    active, suppressed = _rules(root)
    assert "GHA-002" not in active
    assert suppressed == ["GHA-002"]


def test_marker_without_a_reason_suppresses_nothing(tmp_path: Path) -> None:
    root = _workflow(tmp_path, "      # agent-bom: ignore[GHA-002]\n")
    active, suppressed = _rules(root)
    assert "GHA-002" in active
    assert suppressed == []


def test_marker_for_another_rule_suppresses_nothing(tmp_path: Path) -> None:
    root = _workflow(tmp_path, "      # agent-bom: ignore[GHA-001] wrong rule\n")
    active, _suppressed = _rules(root)
    assert "GHA-002" in active


def test_no_marker_leaves_the_finding_active(tmp_path: Path) -> None:
    active, suppressed = _rules(_workflow(tmp_path, ""))
    assert "GHA-002" in active
    assert suppressed == []
