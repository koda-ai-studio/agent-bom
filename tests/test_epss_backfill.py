"""Bounded live EPSS backfill for CVEs the local table and cache left unscored.

Reproduces the ``--enrich`` gap where a CVE missing from a stale local
``epss_scores`` table stayed ``epss_score=None`` although api.first.org had a
score, and pins the bounds of the live step: 100 CVEs per request, a hard cap
on requests per scan, a per-request timeout, fail-open to ``None`` with a
coverage note, zero network under ``--offline``, and a freshness label naming
which EPSS source answered.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import agent_bom.cli  # noqa: F401  # agent_bom.enrichment cannot be the first agent_bom import (import cycle)
from agent_bom import enrichment
from agent_bom.models import Severity, Vulnerability
from agent_bom.scanners import epss_backfill
from agent_bom.scanners.state import consume_scan_warnings, peek_scan_warnings
from agent_bom.vuln_freshness import VulnDataFreshness

_FIRST_SCORES = {"CVE-2026-115774": "0.004300000", "CVE-2026-104844": "0.003890000"}


@pytest.fixture(autouse=True)
def _isolated_enrichment_state(tmp_path, monkeypatch):
    monkeypatch.setattr(enrichment, "_ENRICHMENT_CACHE_DIR", tmp_path)
    monkeypatch.setattr(enrichment, "_KEV_CACHE_FILE", tmp_path / "kev_cache.json")
    monkeypatch.setattr(enrichment, "_nvd_file_cache", {})
    monkeypatch.setattr(enrichment, "_epss_file_cache", {})
    monkeypatch.setattr(enrichment, "_enrichment_cache_loaded", True)
    monkeypatch.setattr(enrichment, "_offline_bundle_epss_loaded", False)
    monkeypatch.setattr(enrichment, "_kev_cache", None)
    monkeypatch.setattr(enrichment, "_kev_cache_time", None)
    monkeypatch.delenv("AGENT_BOM_VULN_DB_OFFLINE", raising=False)
    consume_scan_warnings()
    epss_backfill.reset_epss_state()
    yield
    consume_scan_warnings()
    epss_backfill.reset_epss_state()


def _first_response(cves: list[str]) -> MagicMock:
    response = MagicMock()
    response.status_code = 200
    response.headers = {}
    response.json.return_value = {
        "data": [
            {"cve": cve, "epss": _FIRST_SCORES.get(cve, "0.010000000"), "percentile": "0.371710000", "date": "2026-10-28"} for cve in cves
        ]
    }
    return response


def _recording_request(calls: list[dict], *, fail: bool = False):
    async def _request(client, method, url, **kwargs):
        calls.append({"url": url, **kwargs})
        if fail:
            return None  # request_with_retry: retries exhausted (timeout / connection error)
        return _first_response(kwargs["params"]["cve"].split(","))

    return _request


def _vulns() -> tuple[Vulnerability, Vulnerability]:
    local = Vulnerability(
        id="CVE-2024-1111", summary="scored by the local table", severity=Severity.HIGH, epss_score=0.1, epss_cve_id="CVE-2024-1111"
    )
    missing = Vulnerability(
        id="GHSA-xxxx-yyyy-zzzz", summary="newer than the local table", severity=Severity.HIGH, aliases=["CVE-2026-115774"]
    )
    return local, missing


async def _enrich(vulns: list[Vulnerability], **kwargs) -> int:
    with patch.object(enrichment, "fetch_cisa_kev_catalog", AsyncMock(return_value={})):
        return await enrichment.enrich_vulnerabilities(vulns, enable_nvd=False, enable_epss=True, enable_kev=True, **kwargs)


# ── root cause: a cached entry without a score must not short-circuit the live fetch ──


@pytest.mark.asyncio
async def test_cached_null_score_does_not_short_circuit_live_fetch():
    enrichment._epss_file_cache["CVE-2026-115774"] = {"score": None, "percentile": None, "date": None, "_cached_at": time.time()}
    calls: list[dict] = []
    with patch.object(enrichment, "request_with_retry", _recording_request(calls)):
        scores = await enrichment.fetch_epss_scores(["CVE-2026-115774"], AsyncMock())
    assert len(calls) == 1
    assert scores["CVE-2026-115774"]["score"] == pytest.approx(0.0043)
    assert enrichment._epss_file_cache["CVE-2026-115774"]["score"] == pytest.approx(0.0043)


# ── the --enrich path backfills only what local table + cache left unscored ──


@pytest.mark.asyncio
async def test_enrich_backfills_unscored_cves_from_first_api():
    local, missing = _vulns()
    calls: list[dict] = []
    with patch.object(enrichment, "request_with_retry", _recording_request(calls)):
        await _enrich([local, missing])

    assert missing.epss_score == pytest.approx(0.0043)
    assert missing.epss_cve_id == "CVE-2026-115774"
    assert missing.exploitability is not None
    assert local.epss_score == 0.1, "a CVE the local table already scored is not re-requested"
    assert [call["params"]["cve"] for call in calls] == ["CVE-2026-115774"]
    assert calls[0]["timeout"] == epss_backfill.EPSS_BACKFILL_TIMEOUT_SECONDS
    assert not [w for w in peek_scan_warnings() if "EPSS" in w]

    summary = epss_backfill.epss_source_summary()
    assert summary is not None
    assert summary.to_dict() == {
        "source": "FIRST EPSS",
        "local_table": 1,
        "cache": 0,
        "live_backfill": 1,
        "unscored": 0,
        "requests": 1,
        "capped": 0,
    }


@pytest.mark.asyncio
async def test_enrich_answers_from_cache_before_the_network():
    local, missing = _vulns()
    enrichment._epss_file_cache["CVE-2026-115774"] = {"score": 0.02, "percentile": 0.5, "date": "2026-10-20", "_cached_at": time.time()}
    calls: list[dict] = []
    with patch.object(enrichment, "request_with_retry", _recording_request(calls)):
        await _enrich([local, missing])
    assert calls == []
    assert missing.epss_score == 0.02
    summary = epss_backfill.epss_source_summary()
    assert summary is not None and (summary.cache, summary.live_backfill, summary.requests) == (1, 0, 0)


# ── bounds: 100 CVEs per request, hard request cap per scan ──


@pytest.mark.asyncio
async def test_250_cves_take_three_requests_of_at_most_100():
    cve_ids = [f"CVE-2026-{n:06d}" for n in range(250)]
    calls: list[dict] = []
    errors: list = []
    with patch.object(enrichment, "request_with_retry", _recording_request(calls)):
        scores = await enrichment.fetch_epss_scores(cve_ids, AsyncMock(), errors=errors)
    sizes = [len(call["params"]["cve"].split(",")) for call in calls]
    assert sizes == [100, 100, 50]
    assert len(scores) == 250
    assert errors == []


@pytest.mark.asyncio
async def test_request_cap_leaves_the_remainder_unscored_with_a_coverage_note():
    cve_ids = [f"CVE-2026-{n:06d}" for n in range(250)]
    calls: list[dict] = []
    errors: list = []
    with patch.object(enrichment, "request_with_retry", _recording_request(calls)):
        outcome = await epss_backfill.fetch_epss_batches(
            cve_ids, AsyncMock(), request_fn=enrichment.request_with_retry, errors=errors, max_requests=2
        )
    assert len(calls) == 2
    assert outcome.requests == 2
    assert outcome.capped == 50
    assert len(outcome.scores) == 200
    assert [(e.source, e.kind, e.affected, e.retryable) for e in errors] == [("epss", "request_cap", 50, True)]


def test_default_cap_is_documented_and_sane():
    assert epss_backfill.EPSS_BACKFILL_BATCH_SIZE == 100
    assert epss_backfill.EPSS_BACKFILL_MAX_REQUESTS * epss_backfill.EPSS_BACKFILL_BATCH_SIZE == 2000
    assert 0 < epss_backfill.EPSS_BACKFILL_TIMEOUT_SECONDS <= 30


# ── failure modes: fail open to None, record the gap, never fabricate ──


@pytest.mark.asyncio
async def test_timeout_fails_open_to_null_with_coverage_note():
    local, missing = _vulns()
    calls: list[dict] = []
    with patch.object(enrichment, "request_with_retry", _recording_request(calls, fail=True)):
        await _enrich([local, missing])
    assert len(calls) == 1
    assert missing.epss_score is None
    assert local.epss_score == 0.1
    assert "EPSS incomplete: 1 of 1 CVE(s) not retrieved (unavailable)" in peek_scan_warnings()
    summary = epss_backfill.epss_source_summary()
    assert summary is not None and (summary.unscored, summary.live_backfill, summary.requests) == (1, 0, 1)


@pytest.mark.asyncio
async def test_offline_makes_zero_http_calls():
    local, missing = _vulns()
    calls: list[dict] = []
    with patch.object(enrichment, "request_with_retry", _recording_request(calls)):
        await _enrich([local, missing], offline=True)
    assert calls == []
    assert missing.epss_score is None
    summary = epss_backfill.epss_source_summary()
    assert summary is not None and summary.to_dict() == {
        "source": "FIRST EPSS",
        "local_table": 1,
        "cache": 0,
        "live_backfill": 0,
        "unscored": 1,
        "requests": 0,
        "capped": 0,
    }


# ── freshness label: the report states which EPSS source answered ──


def test_vuln_data_freshness_carries_the_epss_source_label():
    summary = epss_backfill.EpssSourceSummary(local_table=106, cache=0, live_backfill=100, unscored=0, requests=1, capped=0)
    payload = VulnDataFreshness(mode="local", sources=["OSV", "EPSS"]).to_dict(epss_source=summary.to_dict())
    assert payload["epss"] == summary.to_dict()
    assert "epss" not in VulnDataFreshness(mode="local").to_dict()
    assert summary.label() == "EPSS sources: 106 local table, 0 cache, 100 live backfill, 0 unscored (1 request(s))"


def test_report_attaches_the_epss_source_to_vuln_data_freshness():
    from agent_bom.cli.agents.scan_pipeline import report as report_stage

    epss_backfill.record_epss_source_summary(
        epss_backfill.EpssSourceSummary(local_table=1, cache=0, live_backfill=1, unscored=0, requests=1, capped=0)
    )
    st = SimpleNamespace(
        vuln_freshness=VulnDataFreshness(mode="local", sources=["OSV", "EPSS"]),
        report=SimpleNamespace(scan_performance_data=None, vuln_data_freshness=None),
        ctx=None,
    )
    with patch.object(report_stage, "attach_context_evidence"):
        report_stage._attach_context_data(SimpleNamespace(), st)
    assert st.report.vuln_data_freshness["epss"]["live_backfill"] == 1
    assert st.report.vuln_data_freshness["epss"]["source"] == "FIRST EPSS"
