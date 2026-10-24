"""CLI ``check`` must not call an unpublished pinned version clean (parity with MCP ``check``)."""

from __future__ import annotations

import json

from click.testing import CliRunner

from agent_bom.cli import main


def _no_vulns(monkeypatch):
    async def _scan_packages(pkgs, **_kwargs):
        for pkg in pkgs:
            pkg.vulnerabilities = []

    monkeypatch.setattr("agent_bom.scanners.scan_packages", _scan_packages)
    monkeypatch.setattr("agent_bom.parsers.os_parsers.enrich_os_package_context", lambda pkg: True)


def _registry(monkeypatch, *, published: bool, malware_ids: list[str]):
    calls: list[tuple[str, str, str]] = []

    async def _version_published(name, version, ecosystem, _client):
        calls.append((name, version, ecosystem))
        return published

    async def _malicious_name_advisories(_name, _ecosystem, _client):
        return list(malware_ids)

    monkeypatch.setattr("agent_bom.cli._check_published.version_published", _version_published)
    monkeypatch.setattr("agent_bom.mcp_tools.check_lookup.malicious_name_advisories", _malicious_name_advisories)
    return calls


def test_unpublished_version_of_a_malware_name_is_malicious(monkeypatch):
    _no_vulns(monkeypatch)
    _registry(monkeypatch, published=False, malware_ids=["GHSA-c2m4-w5hm-vqjw"])

    result = CliRunner().invoke(main, ["check", "crossenv@6.1.1", "--ecosystem", "npm", "--format", "json"])

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["verdict"] == "malicious"
    assert "GHSA-c2m4-w5hm-vqjw" in payload["message"]
    assert "not published" in payload["message"]


def test_unpublished_version_is_not_clean(monkeypatch):
    _no_vulns(monkeypatch)
    _registry(monkeypatch, published=False, malware_ids=[])

    result = CliRunner().invoke(main, ["check", "requests@99.0.0", "--ecosystem", "pypi", "--format", "json"])

    assert result.exit_code == 2, result.output
    payload = json.loads(result.output)
    assert payload["verdict"] == "unknown"
    assert "not found in the pypi registry" in payload["message"]


def test_published_version_with_no_vulns_stays_clean(monkeypatch):
    _no_vulns(monkeypatch)
    calls = _registry(monkeypatch, published=True, malware_ids=[])

    result = CliRunner().invoke(main, ["check", "requests@2.32.3", "--ecosystem", "pypi"])

    assert result.exit_code == 0, result.output
    assert "No known vulnerabilities" in result.output
    assert calls == [("requests", "2.32.3", "pypi")]


def test_offline_check_never_queries_the_registry(monkeypatch):
    _no_vulns(monkeypatch)
    calls = _registry(monkeypatch, published=False, malware_ids=["GHSA-c2m4-w5hm-vqjw"])

    CliRunner().invoke(main, ["check", "crossenv@6.1.1", "--ecosystem", "npm", "--offline", "--allow-stale-db"])

    assert calls == []
