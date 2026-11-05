"""`scripts/check_plugin_submission_ready.py` stops a submission that would ship stale pins or draft pages."""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("check_plugin_submission_ready", ROOT / "scripts" / "check_plugin_submission_ready.py")
assert SPEC and SPEC.loader
gate = importlib.util.module_from_spec(SPEC)
sys.modules["check_plugin_submission_ready"] = gate
SPEC.loader.exec_module(gate)


def _copy_tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    for relative in ("integrations/claude-code", "integrations/agent-bom-guard", "integrations/codex"):
        shutil.copytree(ROOT / relative, root / relative)
    (root / "site-docs").mkdir(parents=True)
    for page in ("privacy.md", "terms.md"):
        shutil.copy(ROOT / "site-docs" / page, root / "site-docs" / page)
    return root


def _set_release(root: Path, version: str) -> None:
    for paths in gate.pinned_versions(root).values():
        for path in paths:
            text = re.sub(r"(agent-bom(?:\[[a-z]+\])?==)\d[^\s\"',`]*", rf"\g<1>{version}", path.read_text(encoding="utf-8"))
            path.write_text(text, encoding="utf-8")
    for manifest in gate.MANIFESTS:
        target = root / manifest
        data = json.loads(target.read_text(encoding="utf-8"))
        data["version"] = version
        target.write_text(json.dumps(data), encoding="utf-8")
    lock = root / "integrations/claude-code/uv.lock"
    lock.write_text(f'[[package]]\nname = "agent-bom"\nversion = "{version}"\n', encoding="utf-8")


def _publish_pages(root: Path) -> None:
    for page in ("privacy.md", "terms.md"):
        path = root / "site-docs" / page
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if not line.startswith(">")]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_current_tree_is_blocked_on_the_stale_release_and_draft_pages() -> None:
    problems = gate.problems(ROOT)
    assert any(gate.MINIMUM_RELEASE in problem for problem in problems)
    assert any("privacy.md" in problem and "draft" in problem.lower() for problem in problems)
    assert gate.main(["--root", str(ROOT)]) == 1


def test_a_release_above_the_floor_with_published_pages_passes(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _set_release(root, gate.MINIMUM_RELEASE)
    _publish_pages(root)
    assert gate.problems(root) == []
    assert gate.main(["--root", str(root)]) == 0


def test_a_single_stale_pin_is_named(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _set_release(root, gate.MINIMUM_RELEASE)
    _publish_pages(root)
    (root / "integrations/claude-code/pyproject.toml").write_text('dependencies = ["agent-bom==0.113.2"]\n', encoding="utf-8")
    problems = gate.problems(root)
    assert any("0.113.2" in problem for problem in problems)


def test_draft_marker_is_found_even_after_release(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _set_release(root, gate.MINIMUM_RELEASE)
    assert any("draft" in problem.lower() for problem in gate.problems(root))


def test_missing_review_cases_block(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _set_release(root, gate.MINIMUM_RELEASE)
    _publish_pages(root)
    (root / "integrations/codex/review-cases.json").unlink()
    assert any("review-cases" in problem for problem in gate.problems(root))


@pytest.mark.parametrize("version", ["0.113.2", "0.9.9", "not-a-version"])
def test_versions_below_or_outside_the_floor_are_stale(version: str) -> None:
    assert not gate.at_least(version, gate.MINIMUM_RELEASE)
