"""Distribution boundaries for optional integrations and the API server."""

import tomllib
from pathlib import Path

from packaging.requirements import Requirement

PROJECT = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())["project"]


def test_sca_import_extra_exists_and_mirrors_legacy_name():
    extras = PROJECT["optional-dependencies"]
    assert "sca-import" in extras
    assert extras["sca-import"] == extras["snyk"] == []


def test_base_install_does_not_require_unused_web_frameworks():
    dependencies = {Requirement(value).name.lower() for value in PROJECT["dependencies"]}
    assert dependencies.isdisjoint({"flask", "tornado", "werkzeug"})


def test_api_extra_preserves_the_path_jail_dependency_and_security_floor():
    extras = PROJECT["optional-dependencies"]
    dependencies = {Requirement(value).name.lower(): Requirement(value) for value in extras["api"]}
    assert "werkzeug" in dependencies
    assert "3.1.9" in dependencies["werkzeug"].specifier
    assert "3.1.8" not in dependencies["werkzeug"].specifier
    assert "agent-bom[api]" in extras["ui"]


def test_dev_extra_includes_the_api_runtime_its_tests_import():
    assert "agent-bom[api]" in PROJECT["optional-dependencies"]["dev"]
