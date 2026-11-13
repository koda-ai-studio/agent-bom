"""Contract tests for scripts/assemble_changelog.py (per-PR changelog fragments)."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "assemble_changelog.py"
REPO = "https://github.com/koda-ai-studio/agent-bom"

CHANGELOG = f"""# Changelog

All notable changes to agent-bom are documented here.

---

## [Unreleased]

## [1.2.0] - 2026-01-01

### Fixed
- Older fix.

[Unreleased]: {REPO}/compare/v1.2.0...HEAD
[1.2.0]: {REPO}/compare/v1.1.0...v1.2.0
"""


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("assemble_changelog", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _layout(tmp_path: Path, fragments: dict[str, str], changelog: str = CHANGELOG) -> tuple[Path, Path]:
    changelog_path = tmp_path / "CHANGELOG.md"
    changelog_path.write_text(changelog, encoding="utf-8")
    fragment_dir = tmp_path / "changelog.d"
    fragment_dir.mkdir()
    (fragment_dir / "README.md").write_text("# How to write a fragment\n\n### Fixed\n- not a fragment\n", encoding="utf-8")
    for name, text in fragments.items():
        (fragment_dir / name).write_text(text, encoding="utf-8")
    return changelog_path, fragment_dir


def _run(module: ModuleType, changelog: Path, fragments: Path, *extra: str) -> int:
    return module.main(["--changelog", str(changelog), "--fragments-dir", str(fragments), *extra])


def test_fragments_fold_into_a_version_section_in_canonical_order(tmp_path: Path) -> None:
    module = _module()
    changelog, fragments = _layout(
        tmp_path,
        {
            "b-fix.md": "### Fixed\n- Second fix,\n  wrapped onto a continuation line.\n",
            "a-feature.md": "### Fixed\n- First fix.\n\n### Added\n- A new thing.\n",
            "c-security.md": "### Security\n- Tighter check.\n",
        },
    )

    assert _run(module, changelog, fragments, "--version", "1.3.0", "--date", "2026-02-02") == 0

    text = changelog.read_text(encoding="utf-8")
    unreleased, rest = text.split("## [1.3.0] - 2026-02-02\n", 1)
    assert unreleased.rstrip().endswith("## [Unreleased]"), "Unreleased must be left empty above the new section"
    section = rest.split("## [1.2.0]", 1)[0]
    assert section == (
        "\n### Added\n- A new thing.\n\n"
        "### Fixed\n- First fix.\n- Second fix,\n  wrapped onto a continuation line.\n\n"
        "### Security\n- Tighter check.\n\n"
    )
    assert f"[Unreleased]: {REPO}/compare/v1.3.0...HEAD\n[1.3.0]: {REPO}/compare/v1.2.0...v1.3.0\n" in text
    assert "### Fixed\n- Older fix." in text, "existing history must be untouched"
    remaining = sorted(path.name for path in fragments.iterdir())
    assert remaining == ["README.md"], "assembled fragments are deleted; the README stays"


def test_direct_unreleased_entries_are_kept_ahead_of_fragments(tmp_path: Path) -> None:
    module = _module()
    legacy = CHANGELOG.replace("## [Unreleased]\n", "## [Unreleased]\n\n### Fixed\n- Edited in place.\n")
    changelog, fragments = _layout(tmp_path, {"x.md": "### Fixed\n- From a fragment.\n"}, legacy)

    assert _run(module, changelog, fragments, "--version", "1.3.0", "--date", "2026-02-02") == 0

    text = changelog.read_text(encoding="utf-8")
    assert "## [Unreleased]\n\n## [1.3.0] - 2026-02-02\n\n### Fixed\n- Edited in place.\n- From a fragment.\n\n## [1.2.0]" in text


def test_dry_run_prints_and_changes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    module = _module()
    changelog, fragments = _layout(tmp_path, {"x.md": "### Added\n- Thing.\n"})

    assert _run(module, changelog, fragments, "--version", "1.3.0", "--date", "2026-02-02", "--dry-run") == 0

    assert changelog.read_text(encoding="utf-8") == CHANGELOG
    assert (fragments / "x.md").exists()
    assert "## [1.3.0] - 2026-02-02" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ("- No heading at all.\n", "before the first"),
        ("### Fixd\n- Typo in the section.\n", "unknown section"),
        ("### Fixed\n\n### Added\n- Only one has bullets.\n", "empty"),
        ("## [9.9.9]\n### Fixed\n- Version heading.\n", "before the first"),
        ("", "empty"),
    ],
)
def test_malformed_fragments_fail_check_and_assembly(tmp_path: Path, body: str, reason: str, capsys: pytest.CaptureFixture[str]) -> None:
    module = _module()
    changelog, fragments = _layout(tmp_path, {"bad.md": body})

    assert _run(module, changelog, fragments, "--check") == 1
    assert reason in capsys.readouterr().out
    assert _run(module, changelog, fragments, "--version", "1.3.0") == 1
    assert changelog.read_text(encoding="utf-8") == CHANGELOG
    assert (fragments / "bad.md").exists()


def test_check_accepts_valid_fragments_and_an_empty_directory(tmp_path: Path) -> None:
    module = _module()
    changelog, fragments = _layout(tmp_path, {"ok.md": "### Changed\n- Fine.\n"})
    assert _run(module, changelog, fragments, "--check") == 0
    (fragments / "ok.md").unlink()
    assert _run(module, changelog, fragments, "--check") == 0


def test_expect_empty_fails_while_fragments_are_pending(tmp_path: Path) -> None:
    """Release preflight: no fragment may be left behind once a version is cut."""
    module = _module()
    changelog, fragments = _layout(tmp_path, {"ok.md": "### Changed\n- Fine.\n"})
    assert _run(module, changelog, fragments, "--check", "--expect-empty") == 1
    (fragments / "ok.md").unlink()
    assert _run(module, changelog, fragments, "--check", "--expect-empty") == 0


def test_existing_version_is_refused(tmp_path: Path) -> None:
    module = _module()
    changelog, fragments = _layout(tmp_path, {"x.md": "### Added\n- Thing.\n"})

    assert _run(module, changelog, fragments, "--version", "1.2.0") == 1
    assert changelog.read_text(encoding="utf-8") == CHANGELOG
    assert (fragments / "x.md").exists()


def test_nothing_to_assemble_is_an_error(tmp_path: Path) -> None:
    module = _module()
    changelog, fragments = _layout(tmp_path, {})
    assert _run(module, changelog, fragments, "--version", "1.3.0") == 1
    assert changelog.read_text(encoding="utf-8") == CHANGELOG


def test_repository_fragments_are_valid() -> None:
    """The committed changelog.d/ must always assemble; CI runs the same check."""
    assert _module().main(["--check"]) == 0


def test_script_is_stdlib_only() -> None:
    import ast

    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    imported |= {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    import sys

    assert imported <= set(sys.stdlib_module_names) | {"__future__"}, imported
