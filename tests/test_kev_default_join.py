"""A default scan joins CISA KEV; an unavailable catalog is "unknown", never "not listed"."""

from __future__ import annotations

import pytest

from agent_bom.enrichment_posture import reset_enrichment_posture_for_tests
from agent_bom.models import Agent, AgentType, BlastRadius, MCPServer, Package, Severity, Vulnerability

_KEV = {"CVE-2023-4863": {"date_added": "2023-09-13", "due_date": "2023-10-04"}}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    from agent_bom import enrichment

    reset_enrichment_posture_for_tests()
    monkeypatch.setattr(enrichment, "_kev_cache", None)
    monkeypatch.setattr(enrichment, "_kev_cache_time", None)
    monkeypatch.delenv("AGENT_BOM_KEV_DEFAULT_JOIN", raising=False)
    yield
    reset_enrichment_posture_for_tests()


def _estate() -> tuple[list[Agent], list[BlastRadius]]:
    webp = Vulnerability(id="CVE-2023-4863", summary="libwebp heap overflow", severity=Severity.HIGH, cvss_score=8.8)
    other = Vulnerability(id="CVE-2023-50447", summary="pillow eval", severity=Severity.HIGH, cvss_score=8.1)
    pillow = Package(name="pillow", version="9.0.0", ecosystem="pypi", vulnerabilities=[webp, other])
    server = MCPServer(name="srv", command="python", packages=[pillow])
    agent = Agent(name="agent", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/a.json", mcp_servers=[server])
    radii = []
    for vuln in (webp, other):
        br = BlastRadius(
            vulnerability=vuln, package=pillow, affected_servers=[server], affected_agents=[agent], exposed_credentials=[], exposed_tools=[]
        )
        br.calculate_risk_score()
        radii.append(br)
    return [agent], radii


def _patch_scan(monkeypatch, radii):
    from agent_bom.scanners import package_scan

    async def fake_scan_agents(agents, **_kwargs):
        return list(radii)

    monkeypatch.setattr(package_scan, "scan_agents", fake_scan_agents)


def test_default_scan_joins_kev_without_enrich(monkeypatch):
    from agent_bom import enrichment
    from agent_bom.scanners.package_scan import scan_agents_sync

    async def fake_fetch(_client, **_kwargs):
        enrichment.record_enrichment_source("cisa_kev", "success")
        return _KEV

    monkeypatch.setattr(enrichment, "fetch_cisa_kev_catalog", fake_fetch)
    agents, radii = _estate()
    before = {br.vulnerability.id: br.risk_score for br in radii}
    _patch_scan(monkeypatch, radii)

    result = scan_agents_sync(agents, enable_enrichment=False, offline=False)

    by_id = {br.vulnerability.id: br for br in result}
    webp = by_id["CVE-2023-4863"].vulnerability
    assert webp.is_kev is True and webp.kev_status == "listed" and webp.kev_due_date == "2023-10-04"
    other = by_id["CVE-2023-50447"].vulnerability
    assert other.is_kev is False and other.kev_status == "not_listed"
    assert by_id["CVE-2023-4863"].risk_score > before["CVE-2023-4863"]
    assert result[0].vulnerability.id == "CVE-2023-4863"


def test_offline_default_scan_uses_cache_and_never_fetches(monkeypatch):
    from agent_bom import enrichment
    from agent_bom.scanners.package_scan import scan_agents_sync

    async def boom(_client, **_kwargs):
        raise AssertionError("offline KEV join must not fetch")

    monkeypatch.setattr(enrichment, "fetch_cisa_kev_catalog", boom)
    monkeypatch.setattr(enrichment, "_cached_kev_catalog", lambda **_k: _KEV)
    agents, radii = _estate()
    _patch_scan(monkeypatch, radii)

    result = scan_agents_sync(agents, enable_enrichment=False, offline=True)

    assert {br.vulnerability.id: br.vulnerability.kev_status for br in result} == {
        "CVE-2023-4863": "listed",
        "CVE-2023-50447": "not_listed",
    }


@pytest.mark.parametrize("failure", ["empty", "raises"])
def test_unavailable_catalog_marks_kev_unknown_not_false(monkeypatch, failure):
    from agent_bom import enrichment
    from agent_bom.scanners.package_scan import scan_agents_sync

    async def unavailable(_client, **_kwargs):
        if failure == "raises":
            raise RuntimeError("network down")
        return {}

    monkeypatch.setattr(enrichment, "fetch_cisa_kev_catalog", unavailable)
    agents, radii = _estate()
    _patch_scan(monkeypatch, radii)

    result = scan_agents_sync(agents, enable_enrichment=False, offline=False)

    assert len(result) == 2
    for br in result:
        assert br.vulnerability.is_kev is False
        assert br.vulnerability.kev_status == "unknown"


def test_kev_status_is_serialized_in_json_rows(monkeypatch):
    from agent_bom.models import AIBOMReport
    from agent_bom.output import to_json

    agents, radii = _estate()
    radii[0].vulnerability.kev_status = "unknown"
    doc = to_json(AIBOMReport(agents=agents, blast_radii=radii))
    rows = {row["vulnerability_id"]: row for row in doc["blast_radius"]}
    assert rows["CVE-2023-4863"]["kev_status"] == "unknown"
    assert rows["CVE-2023-50447"]["kev_status"] is None


def test_cli_matching_reports_kev_hits_without_enrich_or_gate(monkeypatch):
    from io import StringIO
    from types import SimpleNamespace

    from rich.console import Console

    from agent_bom.cli.agents.scan_pipeline import matching

    _agents, radii = _estate()
    radii[0].vulnerability.is_kev = True
    radii[0].vulnerability.kev_status = "listed"
    buffer = StringIO()
    st = SimpleNamespace(blast_radii=radii, con=Console(file=buffer, force_terminal=False, width=200))
    opts = SimpleNamespace(fail_on_kev=False, enrich=False, offline=False, quiet=False)

    matching._join_kev_catalog(opts, st)

    assert "CISA KEV: 1 actively exploited vulnerability" in buffer.getvalue()
