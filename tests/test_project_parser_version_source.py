"""Every project parser records where a concrete package version came from.

A package-lock.json or pom.xml version is lockfile/manifest evidence; reporting
``version_source: unknown`` for it understated confidence and hid provenance.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.asset_provenance import package_version_provenance
from agent_bom.parsers.project_packages import parse_project_packages

_NPM_LOCK = {
    "name": "demo",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "demo", "version": "1.0.0", "dependencies": {"lodash": "^4.17.20"}},
        "node_modules/lodash": {"version": "4.17.20"},
    },
}

_POM = """<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>a</groupId><artifactId>b</artifactId><version>1</version>
<dependencies><dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId>
<version>2.9.8</version></dependency></dependencies></project>
"""

# (fixture files, package name, expected canonical version_source)
_CASES = {
    "npm-lock": (
        {"package.json": json.dumps({"name": "demo", "dependencies": {"lodash": "^4.17.20"}}), "package-lock.json": json.dumps(_NPM_LOCK)},
        "lodash",
        "lockfile",
    ),
    "maven-pom": ({"pom.xml": _POM}, "com.fasterxml.jackson.core:jackson-databind", "command_pin"),
    "pip-requirements": ({"requirements.txt": "requests==2.31.0\n"}, "requests", "command_pin"),
    "yarn-lock": (
        {"package.json": json.dumps({"name": "d", "dependencies": {"ms": "^2.1.2"}}), "yarn.lock": '"ms@^2.1.2":\n  version "2.1.3"\n'},
        "ms",
        "lockfile",
    ),
    "cargo-lock": (
        {
            "Cargo.toml": '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0"\n',
            "Cargo.lock": (
                'version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\n\n[[package]]\nname = "serde"\nversion = "1.0.200"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            ),
        },
        "serde",
        "lockfile",
    ),
    "go-mod": ({"go.mod": "module example.com/app\n\ngo 1.22\n\nrequire github.com/pkg/errors v0.9.1\n"}, "github.com/pkg/errors", None),
    "ruby-gemfile-lock": (
        {
            "Gemfile": 'source "https://rubygems.org"\ngem "rack"\n',
            "Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.0.8)\n\nDEPENDENCIES\n  rack\n",
        },
        "rack",
        "lockfile",
    ),
    "php-composer-lock": (
        {
            "composer.json": json.dumps({"require": {"monolog/monolog": "^3.0"}}),
            "composer.lock": json.dumps({"packages": [{"name": "monolog/monolog", "version": "3.5.0"}]}),
        },
        "monolog/monolog",
        "lockfile",
    ),
    "pub-lock": (
        {"pubspec.lock": 'packages:\n  http:\n    dependency: "direct main"\n    source: hosted\n    version: "1.2.0"\n'},
        "http",
        "lockfile",
    ),
    "hex-lock": ({"mix.lock": '%{\n  "jason": {:hex, :jason, "1.4.1", "hash", [:mix], [], "hexpm", "hash2"},\n}\n'}, "jason", "lockfile"),
}


def _write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        (root / name).write_text(text, encoding="utf-8")


@pytest.mark.parametrize("case", sorted(_CASES))
def test_parser_sets_version_source_for_concrete_versions(case: str, tmp_path: Path) -> None:
    files, name, expected = _CASES[case]
    _write(tmp_path, files)
    packages = {p.name: p for p in parse_project_packages(tmp_path)}
    assert name in packages, sorted(packages)
    provenance = package_version_provenance(packages[name])
    if expected is None:
        assert provenance["version_source"] != "unknown"
    else:
        assert provenance["version_source"] == expected


def test_no_concrete_project_package_is_left_unknown(tmp_path: Path) -> None:
    """Invariant across every fixture: a concrete version never reports an unknown source."""
    for case, (files, _name, _expected) in _CASES.items():
        root = tmp_path / case
        root.mkdir()
        _write(root, files)
        for package in parse_project_packages(root):
            if package.version and package.version not in {"unknown", "latest"} and not any(c in package.version for c in "^~<>=*| ,"):
                assert package_version_provenance(package)["version_source"] != "unknown", (case, package.name, package.version)


def test_manifest_range_without_lockfile_stays_unknown(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"name": "d", "dependencies": {"lodash": "^4.17.20"}}), encoding="utf-8")
    for package in parse_project_packages(tmp_path):
        if package.name == "lodash":
            assert package_version_provenance(package)["version_source"] in {"unknown", "registry_latest"}
