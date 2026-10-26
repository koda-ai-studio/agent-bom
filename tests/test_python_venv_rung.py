"""Ladder rung 2: an unlocked project's own virtualenv supplies exact installed versions, offline."""

from __future__ import annotations

import os

import pytest

from agent_bom.asset_provenance import package_version_provenance
from agent_bom.parsers.python_parsers import parse_pip_packages
from agent_bom.scanners.state import capture_coverage_warnings


@pytest.fixture(autouse=True)
def _no_registry(monkeypatch):
    def _fail(url):
        raise AssertionError(f"registry contacted although a virtualenv exists: {url}")

    monkeypatch.setattr("agent_bom.parsers.pypi_resolution.fetch_pypi_json", _fail)
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)


def _venv(root, name=".venv", dists=(("requests", "2.32.3"), ("urllib3", "2.2.3"), ("idna", "3.10"))):
    venv = root / name
    site = venv / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\nversion = 3.12.4\n")
    for dist, version in dists:
        info = site / f"{dist.replace('-', '_')}-{version}.dist-info"
        info.mkdir()
        (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {dist}\nVersion: {version}\nRequires-Dist: x\n\nbody Name: evil\n")
    return venv


def _scan(directory):
    with capture_coverage_warnings() as warnings:
        pkgs = parse_pip_packages(directory)
    return {p.name: p for p in pkgs}, warnings


def test_project_venv_supplies_exact_installed_versions_including_transitives(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\ndependencies = ["requests>=2.31"]\n')
    _venv(tmp_path)

    pkgs, warnings = _scan(tmp_path)

    assert {name: p.version for name, p in pkgs.items()} == {"requests": "2.32.3", "urllib3": "2.2.3", "idna": "3.10"}
    assert pkgs["requests"].is_direct is True
    assert pkgs["urllib3"].is_direct is False
    assert pkgs["requests"].declared_version == ">=2.31"
    assert pkgs["urllib3"].purl == "pkg:pypi/urllib3@2.2.3"
    provenance = package_version_provenance(pkgs["urllib3"])
    assert provenance["version_source"] == "installed_environment"
    assert provenance["pinned"] is True
    assert provenance["confidence"] == "exact"
    assert pkgs["urllib3"].version_evidence[0]["type"] == "installed_metadata"
    assert pkgs["urllib3"].version_evidence[0]["source_file"].endswith("urllib3-2.2.3.dist-info/METADATA")
    assert warnings == []


@pytest.mark.parametrize("venv_name", ["venv", "env", "custom-env"])
def test_any_child_directory_with_pyvenv_cfg_is_the_project_venv(tmp_path, venv_name):
    (tmp_path / "requirements.txt").write_text("requests>=2.31\n")
    _venv(tmp_path, venv_name)
    pkgs, warnings = _scan(tmp_path)
    assert pkgs["requests"].version == "2.32.3"
    assert warnings == []


def test_project_itself_is_not_reported_as_its_own_dependency(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "My_Demo"\ndependencies = ["requests"]\n')
    _venv(tmp_path, dists=(("requests", "2.32.3"), ("my-demo", "0.1.0")))
    pkgs, _ = _scan(tmp_path)
    assert set(pkgs) == {"requests"}


def test_declared_requirement_missing_from_venv_is_a_named_gap(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests>=2.31\nflask>=3\npywin32>=300; sys_platform == 'win32'\n")
    _venv(tmp_path)
    pkgs, warnings = _scan(tmp_path)
    assert pkgs["requests"].version == "2.32.3"
    assert pkgs["flask"].version == "unknown"
    [gap] = warnings
    assert "flask" in gap["detail"] and "pywin32" not in gap["detail"]
    assert "not installed" in gap["detail"]


def test_virtual_env_inside_project_root_is_used(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests>=2.31\n")
    venv = _venv(tmp_path / "tools", ".tox-py312")
    monkeypatch.setenv("VIRTUAL_ENV", str(venv))
    pkgs, _ = _scan(tmp_path)
    assert pkgs["requests"].version == "2.32.3"


def test_virtual_env_outside_project_root_is_ignored(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("requests>=2.31\n")
    monkeypatch.setenv("VIRTUAL_ENV", str(_venv(tmp_path, "outside")))
    monkeypatch.setattr("agent_bom.http_client._OFFLINE", True)
    pkgs, warnings = _scan(project)
    assert pkgs["requests"].version == "unknown"
    assert "not resolved offline" in warnings[0]["detail"]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unsupported")
def test_symlinked_venv_escaping_project_root_is_ignored(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("requests>=2.31\n")
    (project / ".venv").symlink_to(_venv(tmp_path, "elsewhere"), target_is_directory=True)
    monkeypatch.setattr("agent_bom.http_client._OFFLINE", True)
    pkgs, warnings = _scan(project)
    assert pkgs["requests"].version == "unknown"
    assert "not resolved offline" in warnings[0]["detail"]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unsupported")
def test_symlinked_dist_info_escaping_project_root_is_skipped(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("requests>=2.31\n")
    venv = _venv(project)
    outside = _venv(tmp_path, "elsewhere", dists=(("secretpkg", "1.0"),))
    site = venv / "lib" / "python3.12" / "site-packages"
    (site / "secretpkg-1.0.dist-info").symlink_to(outside / "lib/python3.12/site-packages/secretpkg-1.0.dist-info")
    pkgs, _ = _scan(project)
    assert "secretpkg" not in pkgs


def test_distribution_count_bound_records_gap(tmp_path, monkeypatch):
    monkeypatch.setattr("agent_bom.parsers.python_venv.MAX_DISTRIBUTIONS", 2)
    (tmp_path / "requirements.txt").write_text("requests>=2.31\n")
    _venv(tmp_path)
    pkgs, warnings = _scan(tmp_path)
    assert len(pkgs) == 2
    assert any("distributions" in w["detail"] for w in warnings)


def test_metadata_body_is_not_parsed_as_headers(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests>=2.31\n")
    _venv(tmp_path)
    pkgs, _ = _scan(tmp_path)
    assert "evil" not in pkgs
