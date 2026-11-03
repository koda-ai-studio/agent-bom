"""``--exclude-dev`` drops lockfile dev-only packages once, so every output and gate agrees."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli.agents.scan_pipeline.dependency_scope import exclude_dev_packages
from agent_bom.models import Package


def _pkg(name: str, scope: str) -> Package:
    return Package(name=name, version="1.0.0", ecosystem="npm", dependency_scope=scope)


def test_only_dev_scopes_are_removed() -> None:
    server = SimpleNamespace(packages=[_pkg("a", "runtime"), _pkg("b", "dev"), _pkg("c", "unknown"), _pkg("d", "test")])
    removed = exclude_dev_packages([SimpleNamespace(mcp_servers=[server])])
    assert removed == 2
    assert [p.name for p in server.packages] == ["a", "c"]


@pytest.fixture
def npm_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    async def clean_lookup(*_args: object, **_kwargs: object) -> int:
        return 0

    monkeypatch.setattr("agent_bom.scanners.scan_packages", clean_lookup)
    root = tmp_path / "app"
    root.mkdir()
    (root / "package.json").write_text(
        json.dumps({"name": "app", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}, "devDependencies": {"jest-mock": "29.7.0"}})
    )
    (root / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "app",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "name": "app",
                        "version": "1.0.0",
                        "dependencies": {"left-pad": "1.3.0"},
                        "devDependencies": {"jest-mock": "29.7.0"},
                    },
                    "node_modules/left-pad": {"version": "1.3.0"},
                    "node_modules/jest-mock": {"version": "29.7.0", "dev": True},
                },
            }
        )
    )
    return root


def _package_names(project: Path, *extra: str) -> set[str]:
    out = project.parent / f"report{len(extra)}.json"
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(project),
            "--no-discover",
            "--no-auto-update-db",
            "--allow-stale-db",
            "--exit-zero",
            "-f",
            "json",
            "-o",
            str(out),
            *extra,
        ],
        catch_exceptions=False,
    )
    assert out.exists(), result.output
    report = json.loads(out.read_text())
    return {pkg["name"] for agent in report["agents"] for server in agent["mcp_servers"] for pkg in server.get("packages", [])}


def test_exclude_dev_removes_dev_packages_from_the_report(npm_project: Path) -> None:
    assert {"left-pad", "jest-mock"} <= _package_names(npm_project)
    names = _package_names(npm_project, "--prod-only")
    assert "left-pad" in names and "jest-mock" not in names
