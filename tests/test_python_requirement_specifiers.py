"""Full PEP 508 specifier sets and markers survive Python manifest parsing."""

from __future__ import annotations

import textwrap

from packaging.specifiers import SpecifierSet

from agent_bom.parsers.python_parsers import parse_pip_compile_inputs, parse_pip_packages
from agent_bom.resolver import _declared_constraint
from agent_bom.transitive import _resolve_pip_version

RELEASES = {"4.6.0": {}, "4.7.1": {}, "4.12.2": {}, "5.0.0": {}, "5.1.0": {}}


def _by_name(pkgs):
    return {p.name: p for p in pkgs}


def test_requirements_txt_keeps_every_specifier(tmp_path):
    (tmp_path / "requirements.txt").write_text("typing-extensions>=4.7.1,<5.0.0\nrequests[socks] >= 2.0, != 2.5.0  # pinned\n")
    pkgs = _by_name(parse_pip_packages(tmp_path))

    spec = SpecifierSet(pkgs["typing-extensions"].declared_version)
    assert "5.1.0" not in spec and "4.12.2" in spec
    assert SpecifierSet(pkgs["requests"].declared_version) == SpecifierSet(">=2.0,!=2.5.0")


def test_registry_resolution_stays_inside_declared_range(tmp_path):
    (tmp_path / "requirements.txt").write_text("typing-extensions>=4.7.1,<5.0.0\n")
    pkg = parse_pip_packages(tmp_path)[0]

    constraint = _declared_constraint(pkg)
    assert constraint is not None
    assert _resolve_pip_version(constraint, RELEASES) == "4.12.2"


def test_pyproject_dependencies_keep_every_specifier(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        textwrap.dedent("""\
            [project]
            name = "demo"
            dependencies = ["cryptography>=3.1.0,<44.0.0", "idna==3.7"]
        """)
    )
    pkgs = _by_name(parse_pip_packages(tmp_path))
    assert SpecifierSet(pkgs["cryptography"].declared_version) == SpecifierSet(">=3.1.0,<44.0.0")
    assert pkgs["idna"].version == "3.7"


def test_markers_that_cannot_apply_are_skipped_and_others_noted(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        textwrap.dedent("""\
            importlib-metadata>=4.0; python_version < "3.8"
            pywin32==306; sys_platform == "win32"
            tomli>=1.1.0; python_version < "3.11"
        """)
    )
    pkgs = _by_name(parse_pip_packages(tmp_path))

    assert "importlib-metadata" not in pkgs
    assert pkgs["pywin32"].version == "306"
    assert any(e.get("type") == "environment_marker" for e in pkgs["pywin32"].version_evidence)
    assert "tomli" in pkgs


def test_pip_compile_inputs_keep_every_specifier(tmp_path):
    (tmp_path / "requirements.in").write_text("urllib3>=1.21.1,<3\n")
    pkg = _by_name(parse_pip_compile_inputs(tmp_path))["urllib3"]
    assert SpecifierSet(pkg.declared_version) == SpecifierSet(">=1.21.1,<3")
