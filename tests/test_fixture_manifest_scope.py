"""Test-fixture and scaffold-template manifests stay out of a locked project's inventory."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.parsers import scan_project_directory
from agent_bom.parsers.fixture_manifests import INCLUDE_ENV, is_fixture_or_template_dir
from agent_bom.scanners.state import peek_coverage_warnings, reset_scan_warnings

_PNPM_LOCK = """lockfileVersion: 5.4

importers:
  .:
    specifiers:
      picocolors: ^1.0.0
    devDependencies:
      picocolors: 1.0.0

packages:
  /picocolors/1.0.0:
    resolution: {integrity: sha512-placeholder}
    dev: true
"""

_POETRY_LOCK = """[[package]]
name = "cleo"
version = "1.0.0a5"
description = ""
optional = false
python-versions = ">=3.7"

[metadata]
lock-version = "1.1"
python-versions = "^3.7"
content-hash = "placeholder"
"""


@pytest.fixture(autouse=True)
def isolated_coverage_state(monkeypatch):
    monkeypatch.delenv(INCLUDE_ENV, raising=False)
    reset_scan_warnings()
    yield
    reset_scan_warnings()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _vite_like(root: Path) -> None:
    _write(root / "package.json", json.dumps({"name": "vite-monorepo", "private": True, "devDependencies": {"picocolors": "^1.0.0"}}))
    _write(root / "pnpm-lock.yaml", _PNPM_LOCK)
    for template in ("template-vue", "template-react-ts"):
        _write(
            root / "packages" / "create-vite" / template / "package.json",
            json.dumps({"name": template, "devDependencies": {"vite": "^4.0.0-beta.3"}}),
        )
    _write(root / "playground" / "templates" / "basic" / "package.json", json.dumps({"dependencies": {"lodash": "^4.17.0"}}))


def _poetry_like(root: Path) -> None:
    _write(root / "pyproject.toml", '[tool.poetry]\nname = "poetry"\nversion = "1.2.0"\n\n[tool.poetry.dependencies]\ncleo = "^1.0.0a5"\n')
    _write(root / "poetry.lock", _POETRY_LOCK)
    _write(
        root / "tests" / "fixtures" / "simple_project" / "pyproject.toml",
        '[tool.poetry]\nname = "simple-project"\nversion = "1.2.3"\n\n[tool.poetry.dependencies]\nrequests = "^2.18"\n',
    )
    with_lock = root / "tests" / "fixtures" / "with-lock"
    _write(with_lock / "pyproject.toml", '[project]\nname = "with-lock"\ndependencies = ["attrs==22.1.0"]\n')
    _write(with_lock / "poetry.lock", _POETRY_LOCK.replace("cleo", "attrs").replace("1.0.0a5", "22.1.0"))


def _names(dir_map) -> dict[str, set[str]]:
    return {str(path): {f"{p.name}@{p.version}" for p in pkgs} for path, pkgs in dir_map.items()}


def _fixture_receipt() -> dict:
    receipts = [w for w in peek_coverage_warnings() if w.get("reason") == "fixture_manifest"]
    assert len(receipts) == 1
    return receipts[0]


def test_vite_like_templates_are_skipped_when_root_is_locked(tmp_path):
    _vite_like(tmp_path)
    dir_map = scan_project_directory(tmp_path)
    assert set(dir_map) == {tmp_path.resolve()}
    assert _names(dir_map)[str(tmp_path.resolve())] == {"picocolors@1.0.0"}
    receipt = _fixture_receipt()
    assert receipt["kind"] == "scope_exclusion"
    assert receipt["excluded_count"] == 3
    assert len(receipt["source_labels"]) == 3


def test_poetry_like_test_fixtures_are_skipped_but_fixture_with_own_lock_is_its_own_project(tmp_path):
    _poetry_like(tmp_path)
    dir_map = scan_project_directory(tmp_path)
    root = tmp_path.resolve()
    with_lock = root / "tests" / "fixtures" / "with-lock"
    assert set(dir_map) == {root, with_lock}
    assert _names(dir_map)[str(root)] == {"cleo@1.0.0a5"}
    assert _names(dir_map)[str(with_lock)] == {"attrs@22.1.0"}
    assert _fixture_receipt()["excluded_count"] == 1


def test_unlocked_project_keeps_template_manifests(tmp_path):
    _vite_like(tmp_path)
    (tmp_path / "pnpm-lock.yaml").unlink()
    dir_map = scan_project_directory(tmp_path)
    assert tmp_path.resolve() / "packages" / "create-vite" / "template-vue" in dir_map
    assert not [w for w in peek_coverage_warnings() if w.get("reason") == "fixture_manifest"]


def test_opt_out_env_keeps_fixture_manifests(tmp_path, monkeypatch):
    _vite_like(tmp_path)
    monkeypatch.setenv(INCLUDE_ENV, "1")
    dir_map = scan_project_directory(tmp_path)
    assert len(dir_map) == 4
    assert not [w for w in peek_coverage_warnings() if w.get("reason") == "fixture_manifest"]


def test_explicit_fixture_root_is_scanned(tmp_path):
    _vite_like(tmp_path)
    template = tmp_path / "packages" / "create-vite" / "template-vue"
    dir_map = scan_project_directory(template)
    assert set(dir_map) == {template.resolve()}
    assert {p.name for p in dir_map[template.resolve()]} == {"vite"}


@pytest.mark.parametrize(
    ("rel", "expected"),
    [
        ("tests/fixtures/simple", True),
        ("test/fixtures/a/b", True),
        ("src/__tests__/__fixtures__/app", True),
        ("lib/__fixtures__/x", True),
        ("spec/fixtures/app", True),
        ("packages/create-vite/template-vue", True),
        ("templates/basic", True),
        ("fixtures/app", False),
        ("src/fixtures", False),
        ("packages/template", False),
        ("packages/templater", False),
        ("tests/integration", False),
        ("packages/app", False),
    ],
)
def test_fixture_dir_classification(rel, expected):
    assert is_fixture_or_template_dir(Path(rel).parts) is expected


def test_skip_warning_lists_relative_paths(tmp_path):
    _vite_like(tmp_path)
    warnings: list[str] = []
    scan_project_directory(tmp_path, warnings=warnings)
    assert warnings == [
        "skipped 3 test-fixture/template manifest directories inside a locked project: "
        "packages/create-vite/template-react-ts, packages/create-vite/template-vue, playground/templates/basic; "
        f"set {INCLUDE_ENV}=1 to include them"
    ]
    assert str(tmp_path) not in warnings[0]
