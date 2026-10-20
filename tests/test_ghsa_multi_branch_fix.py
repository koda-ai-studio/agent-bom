"""GHSA advisories that fix several release lines must remediate on the installed line.

GHSA-r683-j2x4-v87g (CVE-2022-0235, node-fetch) lists two vulnerable windows:
``< 2.6.7`` patched in 2.6.7, and ``>= 3.0.0, < 3.1.1`` patched in 3.1.1.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from agent_bom.models import Package
from agent_bom.scanners.ghsa_advisory import _extract_fixed_version, check_github_advisories

_TWO_LINE_ENTRIES = [
    {"package": {"ecosystem": "npm", "name": "node-fetch"}, "vulnerable_version_range": ">= 3.0.0, < 3.1.1", "patched_versions": "3.1.1"},
    {"package": {"ecosystem": "npm", "name": "node-fetch"}, "vulnerable_version_range": "< 2.6.7", "patched_versions": "2.6.7"},
]


def _advisory(entries: list[dict]) -> dict:
    return {
        "ghsa_id": "GHSA-r683-j2x4-v87g",
        "cve_id": "CVE-2022-0235",
        "summary": "node-fetch forwards secure headers to untrusted sites",
        "severity": "high",
        "cvss": {"score": 8.8},
        "vulnerabilities": entries,
    }


@pytest.mark.parametrize("entries", [_TWO_LINE_ENTRIES, list(reversed(_TWO_LINE_ENTRIES))])
@pytest.mark.parametrize(("installed", "expected"), [("2.6.1", "2.6.7"), ("3.1.0", "3.1.1")])
def test_fix_comes_from_the_window_holding_the_installed_version(entries, installed, expected):
    assert _extract_fixed_version(_advisory(entries), "node-fetch", "npm", current_version=installed) == expected


def test_fix_without_an_installed_version_is_the_lowest_patch():
    assert _extract_fixed_version(_advisory(_TWO_LINE_ENTRIES), "node-fetch", "npm") == "2.6.7"


def test_installed_version_outside_every_window_has_no_fix():
    assert _extract_fixed_version(_advisory(_TWO_LINE_ENTRIES), "node-fetch", "npm", current_version="3.2.0") is None


@pytest.mark.parametrize("entries", [_TWO_LINE_ENTRIES, list(reversed(_TWO_LINE_ENTRIES))])
@pytest.mark.parametrize(("installed", "expected"), [("2.6.1", "2.6.7"), ("3.1.0", "3.1.1")])
def test_scan_reports_the_installed_line_fix_and_never_drops_the_finding(monkeypatch, entries, installed, expected):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    pkg = Package(name="node-fetch", version=installed, ecosystem="npm")

    async def run() -> int:
        with patch("agent_bom.scanners.ghsa_advisory._fetch_advisories_for_package", new_callable=AsyncMock) as fetch:
            fetch.return_value = [_advisory(entries)]
            return await check_github_advisories([pkg])

    assert asyncio.run(run()) == 1
    assert [(vuln.id, vuln.fixed_version) for vuln in pkg.vulnerabilities] == [("CVE-2022-0235", expected)]
