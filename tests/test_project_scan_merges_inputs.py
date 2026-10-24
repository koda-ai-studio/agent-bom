"""An explicit --project is scanned even when other explicit inputs are given."""

from __future__ import annotations

from types import SimpleNamespace

from agent_bom.cli.agents import _discovery_project


def _run(**overrides: object) -> SimpleNamespace:
    base = {"skill_only": False, "project": "/proj", "all_projects": ["/proj"], "images": (), "code_paths": (), "sbom_file": None}
    base.update(overrides)
    return SimpleNamespace(**base)


def test_project_is_scanned_alongside_images_and_code_paths(monkeypatch) -> None:
    scanned: list[str] = []
    monkeypatch.setattr(_discovery_project, "_scan_one_project", lambda run, project, primary: scanned.append(project))

    _discovery_project.scan_project(_run(images=("nginx:1.27",), code_paths=("/proj",)))

    assert scanned == ["/proj"]


def test_skill_only_still_skips_the_project(monkeypatch) -> None:
    scanned: list[str] = []
    monkeypatch.setattr(_discovery_project, "_scan_one_project", lambda run, project, primary: scanned.append(project))

    _discovery_project.scan_project(_run(skill_only=True))

    assert scanned == []
