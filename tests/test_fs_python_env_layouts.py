"""`agent-bom fs` finds installed Python packages wherever an environment keeps them.

A virtualenv root, a bare ``site-packages`` directory, a Windows-layout venv and a
conda-style prefix hold the same ``*.dist-info/METADATA`` files as a system
``usr/local/lib/python3.X/site-packages``; none of them may read as "Nothing to scan".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.filesystem import scan_disk_path_native, scan_filesystem


def _dist(site: Path, name: str, version: str) -> None:
    info = site / f"{name}-{version}.dist-info"
    info.mkdir(parents=True)
    (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\nBody\n")


def _venv(root: Path, site_rel: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "pyvenv.cfg").write_text("home = /usr/bin\nversion = 3.11.9\n")
    site = root / site_rel
    _dist(site, "requests", "2.19.0")
    _dist(site, "urllib3", "1.26.0")
    return site


def _pypi(packages) -> set[tuple[str, str]]:
    return {(p.name, p.version) for p in packages if p.ecosystem == "pypi"}


EXPECTED = {("requests", "2.19.0"), ("urllib3", "1.26.0")}


@pytest.mark.parametrize(
    "site_rel",
    ["lib/python3.11/site-packages", "lib64/python3.12/site-packages", "Lib/site-packages"],
    ids=["posix", "lib64", "windows"],
)
def test_a_virtualenv_root_is_scanned(tmp_path, site_rel):
    _venv(tmp_path / "venv", site_rel)
    packages, strategy = scan_filesystem(str(tmp_path / "venv"))
    assert strategy == "native-dir"
    assert _pypi(packages) == EXPECTED


def test_a_bare_site_packages_directory_is_scanned(tmp_path):
    site = _venv(tmp_path / "venv", "lib/python3.11/site-packages")
    assert _pypi(scan_disk_path_native(site)) == EXPECTED


def test_a_conda_style_prefix_without_pyvenv_cfg_is_scanned(tmp_path):
    _dist(tmp_path / "env" / "lib" / "python3.12" / "site-packages", "numpy", "1.21.0")
    assert _pypi(scan_disk_path_native(tmp_path / "env")) == {("numpy", "1.21.0")}


def test_site_packages_at_an_unlisted_depth_is_still_found(tmp_path):
    _dist(tmp_path / "srv" / "app" / "runtime" / "lib" / "python3.11" / "site-packages", "flask", "0.12.0")
    assert _pypi(scan_disk_path_native(tmp_path)) == {("flask", "0.12.0")}


def test_system_site_packages_are_not_counted_twice(tmp_path):
    _dist(tmp_path / "usr" / "local" / "lib" / "python3.11" / "site-packages", "requests", "2.19.0")
    packages = [p for p in scan_disk_path_native(tmp_path) if p.ecosystem == "pypi"]
    assert [(p.name, p.version) for p in packages] == [("requests", "2.19.0")]


@pytest.mark.parametrize("target", ["venv", "venv/lib/python3.11/site-packages"])
def test_fs_cli_reports_the_installed_packages_not_nothing_to_scan(tmp_path, monkeypatch, target):
    async def no_lookup(*_a, **_k):
        return {}

    monkeypatch.setattr("agent_bom.scanners.query_osv_batch", no_lookup)
    _venv(tmp_path / "venv", "lib/python3.11/site-packages")
    artifact = tmp_path / "r.json"
    result = CliRunner().invoke(main, ["fs", str(tmp_path / target), "-f", "json", "-o", str(artifact)])
    assert result.exit_code == 0, result.output
    report = json.loads(artifact.read_text())
    assert not [i for i in report["scan_run"]["issues"] if i["code"] == "nothing_to_scan"]
    names = {pkg["name"] for agent in report["agents"] for server in agent["mcp_servers"] for pkg in server["packages"]}
    assert {"requests", "urllib3"} <= names


def test_legacy_egg_info_installs_are_read(tmp_path):
    site = tmp_path / "venv" / "lib" / "python3.11" / "site-packages"
    (site / "legacy_pkg-0.9.egg-info").mkdir(parents=True)
    (site / "legacy_pkg-0.9.egg-info" / "PKG-INFO").write_text("Metadata-Version: 1.1\nName: legacy-pkg\nVersion: 0.9\n")
    assert _pypi(scan_disk_path_native(tmp_path / "venv")) == {("legacy-pkg", "0.9")}
