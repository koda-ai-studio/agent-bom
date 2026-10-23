"""OSV/GHSA malicious-package advisories must yield a malicious verdict.

Fixtures are trimmed records recorded from api.osv.dev on 2026-10-23. GitHub's
reviewed malware advisories carry GHSA ids (not MAL- ids); they are marked by
CWE-506 "Embedded Malicious Code" and/or a "... is malware" summary.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from agent_bom.malicious import flag_malicious_from_vulns, is_malicious_osv_record
from agent_bom.models import Package
from agent_bom.scanners.package_scan import build_vulnerabilities

FIXTURES = Path(__file__).parent / "fixtures" / "osv_malicious"


def _record(advisory_id: str) -> dict:
    return json.loads((FIXTURES / f"{advisory_id}.json").read_text())


@pytest.mark.parametrize(
    ("advisory_id", "name", "version"),
    [("GHSA-mh6f-8j2x-4483", "event-stream", "3.3.6"), ("GHSA-c2m4-w5hm-vqjw", "crossenv", "1.0.1")],
)
def test_ghsa_malware_advisory_flags_package_malicious(advisory_id: str, name: str, version: str) -> None:
    pkg = Package(name=name, version=version, ecosystem="npm")
    pkg.vulnerabilities = build_vulnerabilities([_record(advisory_id)], pkg)
    flag_malicious_from_vulns(pkg)
    assert pkg.is_malicious is True
    assert advisory_id in (pkg.malicious_reason or "") or "CVE-2017-16074" in (pkg.malicious_reason or "")


def test_ordinary_ghsa_advisory_is_not_malicious() -> None:
    pkg = Package(name="requests", version="2.19.1", ecosystem="pypi")
    pkg.vulnerabilities = build_vulnerabilities([_record("GHSA-x84v-xcm2-53pg")], pkg)
    flag_malicious_from_vulns(pkg)
    assert pkg.is_malicious is False


@pytest.mark.parametrize(
    "record",
    [
        {"id": "MAL-2024-1", "summary": "anything"},
        {"id": "GHSA-xxxx", "aliases": ["MAL-2022-7"], "summary": "x"},
        {"id": "GHSA-xxxx", "summary": "Malicious Package in flatmap-stream"},
        {"id": "GHSA-xxxx", "summary": "x", "database_specific": {"cwe_ids": ["CWE-506"]}},
    ],
)
def test_malicious_record_shapes(record: dict) -> None:
    assert is_malicious_osv_record(record) is True


@pytest.mark.parametrize(
    "summary",
    ["A malicious user can bypass authentication", "Crafted input from a malicious server causes DoS", "SSRF in fetch"],
)
def test_attacker_wording_is_not_malware(summary: str) -> None:
    assert is_malicious_osv_record({"id": "GHSA-yyyy", "summary": summary, "database_specific": {"cwe_ids": ["CWE-79"]}}) is False


def _trunc(s: str) -> str:
    return s


_CHECK_KW = {"_validate_ecosystem": lambda e: e, "_truncate_response": _trunc}


@pytest.mark.asyncio
async def test_check_unpublished_version_of_malware_package_is_malicious() -> None:
    """crossenv@6.1.1 is unpublished; the package itself only exists as malware."""
    from agent_bom.mcp_tools import scanning

    async def _noop_scan(_pkgs, **_kw):
        return 0

    with (
        patch("agent_bom.scanners.scan_packages", side_effect=_noop_scan),
        patch("agent_bom.mcp_tools.scanning._version_published", new=AsyncMock(return_value=False)),
        patch(
            "agent_bom.mcp_tools.check_lookup._query_osv_by_name",
            new=AsyncMock(return_value=[_record("GHSA-c2m4-w5hm-vqjw")]),
        ),
    ):
        data = json.loads(await scanning.check_impl(package="crossenv@6.1.1", ecosystem="npm", **_CHECK_KW))
    assert data["status"] == "malicious"
    assert data["is_malicious"] is True
    assert "GHSA-c2m4-w5hm-vqjw" in data["malicious_reason"]


@pytest.mark.asyncio
async def test_check_unpublished_version_without_malware_advisory_stays_unknown() -> None:
    from agent_bom.mcp_tools import scanning

    async def _noop_scan(_pkgs, **_kw):
        return 0

    with (
        patch("agent_bom.scanners.scan_packages", side_effect=_noop_scan),
        patch("agent_bom.mcp_tools.scanning._version_published", new=AsyncMock(return_value=False)),
        patch(
            "agent_bom.mcp_tools.check_lookup._query_osv_by_name",
            new=AsyncMock(return_value=[_record("GHSA-x84v-xcm2-53pg")]),
        ),
    ):
        data = json.loads(await scanning.check_impl(package="requests==9.9.9", ecosystem="pypi", **_CHECK_KW))
    assert data["status"] == "unknown"


def test_colourama_is_a_typosquat_of_colorama() -> None:
    from agent_bom.malicious import check_typosquat

    assert check_typosquat("colourama", "pypi") == "colorama"
    assert check_typosquat("colorama", "pypi") is None


@pytest.mark.asyncio
async def test_check_unresolvable_typosquat_name_is_malicious_not_error() -> None:
    """colourama has no registry entry; its name alone is the verdict."""
    from agent_bom.mcp_tools import scanning

    with (
        patch("agent_bom.resolver.resolve_package_version", new=AsyncMock(return_value=False)),
        patch("agent_bom.mcp_tools.check_lookup._query_osv_by_name", new=AsyncMock(return_value=[])),
    ):
        data = json.loads(await scanning.check_impl(package="colourama", ecosystem="pypi", **_CHECK_KW))
    assert data["status"] == "malicious"
    assert "colorama" in data["malicious_reason"]


@pytest.mark.asyncio
async def test_check_unresolvable_malware_only_name_is_malicious() -> None:
    from agent_bom.mcp_tools import scanning

    with (
        patch("agent_bom.resolver.resolve_package_version", new=AsyncMock(return_value=False)),
        patch("agent_bom.mcp_tools.check_lookup._query_osv_by_name", new=AsyncMock(return_value=[_record("GHSA-c2m4-w5hm-vqjw")])),
    ):
        data = json.loads(await scanning.check_impl(package="crossenv", ecosystem="npm", **_CHECK_KW))
    assert data["status"] == "malicious"
    assert "GHSA-c2m4-w5hm-vqjw" in data["malicious_reason"]
