"""Explicit upstream coordinates must not become findings on unrelated packages."""

import pytest

from agent_bom.models import Package
from agent_bom.scanners import build_vulnerabilities


def _advisory(name="shared", ecosystem="npm"):
    return {
        "id": "GHSA-test-boundary",
        "summary": "Fixture advisory",
        "affected": [
            {
                "package": {"name": name, "ecosystem": ecosystem},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
            }
        ],
    }


@pytest.mark.parametrize("name,ecosystem", [("shared", "pypi"), ("other", "npm")])
def test_explicit_other_package_is_not_a_confirmed_match(name, ecosystem):
    assert build_vulnerabilities([_advisory()], Package(name=name, version="1.0", ecosystem=ecosystem)) == []


@pytest.mark.parametrize("version", ["unknown", "UNKNOWN", "latest", "*", ""])
def test_unresolved_version_does_not_confirm_an_advisory(version):
    assert build_vulnerabilities([_advisory()], Package(name="shared", version=version, ecosystem="npm")) == []


def test_withdrawn_advisory_does_not_reappear_from_a_cached_response():
    advisory = {**_advisory(), "withdrawn": "2026-10-15T00:00:00Z"}
    assert build_vulnerabilities([advisory], Package(name="shared", version="1.0", ecosystem="npm")) == []


def test_same_ecosystem_alias_and_version_remain_a_match():
    result = build_vulnerabilities([_advisory("Example_Pkg", "PyPI")], Package(name="example-pkg", version="1.0", ecosystem="pypi"))
    assert len(result) == 1
    assert result[0].fixed_version == "2.0"
