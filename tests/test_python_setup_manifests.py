"""setup.cfg / setup.py declarations are parsed statically, never executed."""

from __future__ import annotations

import textwrap

from packaging.specifiers import SpecifierSet

from agent_bom.parsers import _has_manifest
from agent_bom.parsers.python_parsers import parse_pip_packages
from agent_bom.scanners.state import capture_coverage_warnings

SETUP_CFG = textwrap.dedent("""\
    [metadata]
    name = demo-connector

    [options]
    python_requires = >=3.9
    install_requires =
        asn1crypto>0.24.0,<2.0.0
        cryptography>=3.1.0
        pyOpenSSL>=22.0.0,<25.0.0
        importlib-metadata; python_version < "3.8"

    [options.extras_require]
    pandas =
        pandas>=1.0.0,<3.0.0
    secure-local-storage =
        keyring>=23.1.0,<26.0.0
""")


def _names(pkgs):
    return {p.name.lower(): p for p in pkgs}


def test_setup_cfg_install_requires_and_extras(tmp_path):
    (tmp_path / "setup.cfg").write_text(SETUP_CFG)
    (tmp_path / "pyproject.toml").write_text('[build-system]\nrequires = ["setuptools"]\n')

    pkgs = _names(parse_pip_packages(tmp_path))

    assert set(pkgs) == {"asn1crypto", "cryptography", "pyopenssl", "pandas", "keyring"}
    assert SpecifierSet(pkgs["pyopenssl"].declared_version) == SpecifierSet(">=22.0.0,<25.0.0")


def test_setup_cfg_marks_directory_as_manifest(tmp_path):
    (tmp_path / "setup.cfg").write_text(SETUP_CFG)
    assert _has_manifest(tmp_path)
    (tmp_path / "setup.cfg").unlink()
    (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup()\n")
    assert _has_manifest(tmp_path)


def test_static_setup_py_literal_lists_are_parsed_without_execution(tmp_path):
    marker = tmp_path / "executed"
    (tmp_path / "setup.py").write_text(
        textwrap.dedent(f"""\
            import pathlib
            from setuptools import setup
            pathlib.Path({str(marker)!r}).write_text("ran")
            REQUIRES = ["requests>=2.31,<3", "urllib3==2.2.1"]
            setup(
                name="demo",
                install_requires=REQUIRES,
                extras_require={{"dev": ["pytest>=7"]}},
            )
        """)
    )
    with capture_coverage_warnings() as warnings:
        pkgs = _names(parse_pip_packages(tmp_path))

    assert not marker.exists()
    assert pkgs["urllib3"].version == "2.2.1"
    assert SpecifierSet(pkgs["requests"].declared_version) == SpecifierSet(">=2.31,<3")
    assert "pytest" in pkgs
    # Only the unlocked-manifest gap: no parse or dynamic-declaration gaps.
    assert [w for w in warnings if "transitive dependencies were not resolved" not in str(w["detail"])] == []


def test_dynamic_setup_py_records_coverage_gap(tmp_path):
    (tmp_path / "setup.py").write_text(
        textwrap.dedent("""\
            from setuptools import setup
            def reqs():
                return open("requirements-base.txt").read().splitlines()
            setup(name="demo", install_requires=reqs())
        """)
    )
    with capture_coverage_warnings() as warnings:
        pkgs = parse_pip_packages(tmp_path)

    assert pkgs == []
    assert any("setup.py" in str(w["release"]) and w["reason"] == "manifest_parse_error" for w in warnings)


def test_pyproject_dynamic_dependencies_without_static_source_records_gap(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\ndynamic = ["dependencies", "version"]\n')
    with capture_coverage_warnings() as warnings:
        pkgs = parse_pip_packages(tmp_path)

    assert pkgs == []
    assert any("dynamic" in str(w["detail"]) for w in warnings)


def test_pyproject_dynamic_dependencies_resolved_from_setup_cfg(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\ndynamic = ["dependencies"]\n')
    (tmp_path / "setup.cfg").write_text(SETUP_CFG)
    with capture_coverage_warnings() as warnings:
        pkgs = _names(parse_pip_packages(tmp_path))

    assert "cryptography" in pkgs
    # Only the unlocked-manifest gap: no parse or dynamic-declaration gaps.
    assert [w for w in warnings if "transitive dependencies were not resolved" not in str(w["detail"])] == []
