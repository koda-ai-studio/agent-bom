"""`agent-bom check <pkg>` with no version checks the latest published version.

The MCP ``check`` tool resolves an omitted version to the registry's latest
release and checks that. The CLI used to skip the lookup and report
``incomplete``, so a skill asking for "the latest published version" got no
answer. Both surfaces now resolve it the same way, say which version was
checked (``version_source``), and stay incomplete when the lookup fails.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.models import Package


@pytest.fixture
def clean_scan(monkeypatch: pytest.MonkeyPatch) -> list[Package]:
    scanned: list[Package] = []

    async def _scan_packages(pkgs, **_kwargs):
        for pkg in pkgs:
            pkg.vulnerabilities = []
            scanned.append(pkg)

    async def _published(*_args, **_kwargs) -> bool:
        return True

    monkeypatch.setattr("agent_bom.scanners.scan_packages", _scan_packages)
    monkeypatch.setattr("agent_bom.parsers.os_parsers.enrich_os_package_context", lambda pkg: True)
    monkeypatch.setattr("agent_bom.cli._check_published.version_published", _published)
    return scanned


def _registry_latest(monkeypatch: pytest.MonkeyPatch, latest: str | None, *, malicious_reason: str | None = None) -> list[str]:
    asked: list[str] = []

    async def _resolve(pkg: Package, _client, **_kwargs) -> bool:
        asked.append(pkg.name)
        if latest is None:
            return False
        pkg.version = latest
        pkg.resolved_from_registry = True
        return True

    async def _malware_reason(resolved: bool, *_args, **_kwargs) -> str | None:
        return None if resolved else malicious_reason

    monkeypatch.setattr("agent_bom.resolver.resolve_package_version", _resolve)
    monkeypatch.setattr("agent_bom.mcp_tools.check_lookup.resolution_malware_reason", _malware_reason)
    return asked


def _check(*args: str):
    return CliRunner().invoke(main, ["check", *args, "--format", "json"])


def test_check_without_version_checks_latest_published(monkeypatch: pytest.MonkeyPatch, clean_scan: list[Package]) -> None:
    asked = _registry_latest(monkeypatch, "4.18.2")

    result = _check("express", "--ecosystem", "npm")

    assert asked == ["express"]
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["version"] == "4.18.2"
    assert payload["version_source"] == "registry_latest"
    assert payload["canonical_verdict"] == "clean"
    assert [pkg.version for pkg in clean_scan] == ["4.18.2"]


def test_check_with_explicit_version_reports_requested_source(monkeypatch: pytest.MonkeyPatch, clean_scan: list[Package]) -> None:
    asked = _registry_latest(monkeypatch, "9.9.9")

    result = _check("express@4.17.1", "--ecosystem", "npm")

    assert asked == []
    payload = json.loads(result.output)
    assert payload["version"] == "4.17.1"
    assert payload["version_source"] == "requested"


def test_check_unresolvable_latest_stays_incomplete(monkeypatch: pytest.MonkeyPatch, clean_scan: list[Package]) -> None:
    _registry_latest(monkeypatch, None)

    result = _check("express", "--ecosystem", "npm")

    assert result.exit_code == 2, result.output
    payload = json.loads(result.output)
    assert payload["canonical_verdict"] == "incomplete"
    assert "latest" in payload["message"] and "express" in payload["message"]
    assert clean_scan == []


def test_check_unresolvable_known_malware_name_is_malicious(monkeypatch: pytest.MonkeyPatch, clean_scan: list[Package]) -> None:
    _registry_latest(monkeypatch, None, malicious_reason="Known malicious package (MAL-2025-1)")

    result = _check("evil-removed-pkg", "--ecosystem", "npm")

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["canonical_verdict"] == "malicious"
    assert payload["is_malicious"] is True


def test_offline_check_without_version_still_skips_lookup(monkeypatch: pytest.MonkeyPatch, clean_scan: list[Package]) -> None:
    asked = _registry_latest(monkeypatch, "4.18.2")

    result = _check("express", "--ecosystem", "npm", "--offline")

    assert asked == []
    assert result.exit_code == 2
    assert json.loads(result.output)["exit_code"] == 2


def test_mcp_check_without_version_reports_the_same_version_source(monkeypatch: pytest.MonkeyPatch, clean_scan: list[Package]) -> None:
    _registry_latest(monkeypatch, "4.18.2")
    from agent_bom.mcp_tools.scanning import check_impl

    async def _no_osv_name_lookup(*_args, **_kwargs):
        return []

    monkeypatch.setattr("agent_bom.mcp_tools.check_lookup._query_osv_by_name", _no_osv_name_lookup)

    payload = json.loads(
        asyncio.run(
            check_impl(
                package="express",
                ecosystem="npm",
                _validate_ecosystem=lambda ecosystem: ecosystem,
                _truncate_response=lambda response: response,
            )
        )
    )

    cli = json.loads(_check("express", "--ecosystem", "npm").output)
    assert payload["version"] == cli["version"] == "4.18.2"
    assert payload["version_source"] == cli["version_source"] == "registry_latest"
