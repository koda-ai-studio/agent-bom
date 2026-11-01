"""Package checks reject invalid names while preserving registry name syntax."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli._check_support import _package_spec_error
from agent_bom.security import validate_package_name


@pytest.mark.parametrize("ecosystem", ["npm", "pypi", "go", "cargo"])
@pytest.mark.parametrize("name", ["bad package", "bad\tpackage", "package?query", "package#fragment"])
def test_invalid_known_ecosystem_names_are_rejected(name, ecosystem):
    assert _package_spec_error(name, ecosystem) is not None


@pytest.mark.parametrize("name", ["lodash.merge", "@example.scope/package.name", "LegacyName", "old~package"])
def test_npm_registry_names_remain_supported(name):
    validate_package_name(name, "npm")
    assert _package_spec_error(name, "npm") is None


@pytest.mark.parametrize("ecosystem", ["npm", "pypi", "go", "cargo"])
@pytest.mark.parametrize("output_format", ["console", "json"])
def test_check_rejects_invalid_names_before_scanning(monkeypatch, ecosystem, output_format):
    calls = []

    async def scan_packages(packages, **kwargs):
        calls.append(packages)
        for package in packages:
            package.vulnerabilities = []

    monkeypatch.setattr("agent_bom.scanners.scan_packages", scan_packages)
    result = CliRunner().invoke(main, ["check", "bad package@1.0.0", "--ecosystem", ecosystem, "--format", output_format])

    assert calls == []
    assert result.exit_code == 2
    if output_format == "json":
        payload = json.loads(result.output)
        assert payload["verdict"] == "incomplete"
        assert payload["exit_code"] == 2
    else:
        assert "Invalid" in result.output
        assert "No known vulnerabilities" not in result.output
