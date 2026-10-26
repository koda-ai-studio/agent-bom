"""Unlocked Python manifests resolve only direct declarations: report partial coverage."""

from __future__ import annotations

import json

from agent_bom.parsers.python_parsers import parse_pip_packages
from agent_bom.scanners.state import capture_coverage_warnings

_HASH = "sha256:" + "a" * 64


def _gaps(tmp_path):
    with capture_coverage_warnings() as warnings:
        pkgs = parse_pip_packages(tmp_path)
    return pkgs, [w for w in warnings if "transitive" in str(w.get("detail"))]


def test_setup_cfg_without_lock_records_transitive_gap(tmp_path):
    (tmp_path / "setup.cfg").write_text("[options]\ninstall_requires =\n    requests>=2.31,<3\n    idna\n")
    pkgs, gaps = _gaps(tmp_path)
    assert {p.name for p in pkgs} == {"requests", "idna"}
    assert len(gaps) == 1
    assert gaps[0]["reason"] == "manifest_parse_error"
    assert gaps[0]["release"].endswith("setup.cfg")
    assert "lockfile" in gaps[0]["detail"]


def test_static_setup_py_without_lock_records_transitive_gap(tmp_path):
    (tmp_path / "setup.py").write_text('from setuptools import setup\nsetup(install_requires=["urllib3==2.2.1"])\n')
    _, gaps = _gaps(tmp_path)
    assert len(gaps) == 1 and gaps[0]["release"].endswith("setup.py")


def test_ranged_requirements_without_lock_records_transitive_gap(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests>=2.31\nurllib3==2.2.1\n")
    _, gaps = _gaps(tmp_path)
    assert len(gaps) == 1 and gaps[0]["release"].endswith("requirements.txt")


def test_pyproject_declarations_without_lock_record_transitive_gap(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\ndependencies = ["httpx>=0.27"]\n')
    _, gaps = _gaps(tmp_path)
    assert len(gaps) == 1 and gaps[0]["release"].endswith("pyproject.toml")


def test_hash_pinned_requirements_stay_complete(tmp_path):
    (tmp_path / "requirements.txt").write_text(f"requests==2.32.3 \\\n    --hash={_HASH}\nidna==3.7 --hash={_HASH}\n")
    pkgs, gaps = _gaps(tmp_path)
    assert {p.name: p.version for p in pkgs} == {"requests": "2.32.3", "idna": "3.7"}
    assert gaps == []


def test_fully_pinned_requirements_stay_complete(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\nidna==3.7\n")
    _, gaps = _gaps(tmp_path)
    assert gaps == []


def test_uv_lock_project_stays_complete(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="app"\nversion="0.1.0"\ndependencies=["idna>=3"]\n')
    (tmp_path / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { virtual = "." }\n'
        'dependencies = [{ name = "idna" }]\n[[package]]\nname = "idna"\nversion = "3.7"\n'
    )
    pkgs, gaps = _gaps(tmp_path)
    assert [p.name for p in pkgs] == ["idna"]
    assert gaps == []


def test_poetry_lock_project_stays_complete(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.poetry.dependencies]\npython = "^3.11"\nidna = "^3"\n')
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "idna"\nversion = "3.7"\n')
    pkgs, gaps = _gaps(tmp_path)
    assert [p.name for p in pkgs] == ["idna"]
    assert gaps == []


def test_pipfile_lock_project_stays_complete(tmp_path):
    (tmp_path / "Pipfile.lock").write_text(json.dumps({"default": {"idna": {"version": "==3.7"}}, "develop": {}}))
    pkgs, gaps = _gaps(tmp_path)
    assert [p.name for p in pkgs] == ["idna"]
    assert gaps == []
