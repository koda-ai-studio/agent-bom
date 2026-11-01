"""Analysis tools answer from the session's scan result before any persisted snapshot."""

from __future__ import annotations

import asyncio
import json

import pytest

from agent_bom.mcp_tools.analysis import blast_radius_impl
from agent_bom.mcp_tools.graph import deploy_decision_impl, exposure_paths_impl
from agent_bom.mcp_tools.result_store import DurableScanResultStore
from agent_bom.mcp_tools.session_result import (
    SessionResultError,
    load_session_report,
    session_blast_radius,
    session_deploy_decision,
)

CVE = "CVE-2025-6514"
PATH_ID = "blast:cve-2025-6514:npm:mcp-remote:0.1.15"


def _report(*, kev: bool = False, suppressed: bool = False) -> dict:
    return {
        "scan_id": "scan-1",
        "scan_sources": ["project"],
        "blast_radius": [
            {
                "vulnerability_id": CVE,
                "severity": "critical",
                "cvss_score": 9.6,
                "risk_score": 9.3,
                "package_name": "mcp-remote",
                "package_version": "0.1.15",
                "ecosystem": "npm",
                "affected_servers": ["remote-bridge"],
                "affected_agents": ["project:demo"],
                "exposed_credentials": ["AUTH_TOKEN"],
                "exposed_tools": [],
                "fixed_version": "0.1.16",
                "exposure_path_id": PATH_ID,
                "exposure_path_rank": 1,
                "reachability": "likely",
                "is_kev": kev,
                "suppressed": suppressed,
            }
        ],
        "exposure_paths": {
            "paths": [
                {
                    "id": PATH_ID,
                    "rank": 1,
                    "label": "mcp-remote@0.1.15 -> CVE-2025-6514",
                    "summary": "Code execution reachable from the agent.",
                    "riskScore": 9.3,
                    "severity": "critical",
                    "source": "agent:cfg-1:project%3Ademo",
                    "target": f"vuln:{CVE}",
                    "hops": ["agent:cfg-1:project%3Ademo", "server:cfg-1:remote-bridge", "pkg:npm:mcp-remote@0.1.15", f"vuln:{CVE}"],
                    "nodeIds": ["agent:cfg-1:project%3Ademo", "server:cfg-1:remote-bridge", "pkg:npm:mcp-remote@0.1.15", f"vuln:{CVE}"],
                    "nodeLabels": {"server:cfg-1:remote-bridge": "remote-bridge", "pkg:npm:mcp-remote@0.1.15": "mcp-remote@0.1.15"},
                    "findings": [CVE],
                    "exposedCredentials": ["AUTH_TOKEN"],
                    "fix": "Upgrade mcp-remote to 0.1.16",
                    "suppressed": suppressed,
                }
            ]
        },
    }


def _store(tmp_path) -> DurableScanResultStore:
    return DurableScanResultStore(path=tmp_path / "results.db", tenant_id="default", max_entries=5, ttl_seconds=60)


# ── store ────────────────────────────────────────────────────────────────────


def test_latest_returns_newest_unexpired_result_for_the_owner_only(tmp_path):
    now = [100.0]
    cache = DurableScanResultStore(path=tmp_path / "r.db", tenant_id="default", max_entries=5, ttl_seconds=60, clock=lambda: now[0])
    first = cache.put("caller", {"report": {"scan_id": "a"}})
    now[0] += 1
    second = cache.put("caller", {"report": {"scan_id": "b"}})
    cache.put("other-caller", {"report": {"scan_id": "foreign"}})
    assert cache.latest("caller") == (second, {"report": {"scan_id": "b"}})
    assert first != second
    assert cache.latest("nobody") is None
    now[0] += 120
    assert cache.latest("caller") is None


def test_load_session_report_prefers_explicit_id_and_rejects_unknown(tmp_path):
    cache = _store(tmp_path)
    rid = cache.put("caller", {"report": _report()})
    cache.put("caller", {"report": {"scan_id": "newer"}})
    assert load_session_report(owner="caller", result_id=rid, store=cache)[1]["scan_id"] == "scan-1"
    assert load_session_report(owner="caller", result_id=None, store=cache)[1]["scan_id"] == "newer"
    assert load_session_report(owner="other", result_id=None, store=cache) is None
    with pytest.raises(SessionResultError):
        load_session_report(owner="caller", result_id="missing", store=cache)
    with pytest.raises(SessionResultError):
        load_session_report(owner="other", result_id=rid, store=cache)


# ── projections ──────────────────────────────────────────────────────────────


def test_session_blast_radius_projects_open_rows_and_counts_suppressed():
    answer = session_blast_radius(_report(), "rid-1", CVE)
    assert answer["found"] is True and answer["source"] == "session_scan_result" and answer["result_id"] == "rid-1"
    row = answer["blast_radii"][0]
    assert row["package"] == "mcp-remote@0.1.15" and row["exposed_credentials"] == ["AUTH_TOKEN"] and row["fixed_version"] == "0.1.16"
    assert session_blast_radius(_report(), "rid-1", "CVE-1999-0001") is None
    suppressed = session_blast_radius(_report(suppressed=True), "rid-1", CVE)
    assert suppressed["count"] == 0 and suppressed["suppressed_count"] == 1


@pytest.mark.parametrize("candidate", ["mcp-remote@0.1.15", "MCP-REMOTE", CVE, "remote-bridge", PATH_ID, "pkg:npm:mcp-remote@0.1.15"])
def test_session_deploy_decision_matches_exact_identifiers(candidate):
    verdict = session_deploy_decision(
        _report(), "rid-1", candidate=candidate, tenant_id="default", limit=5, warn_risk=40.0, block_risk=80.0, view="summary"
    )
    assert verdict is not None
    assert verdict["decision"] == "block"  # 9.3 on the 0-10 report scale is 93 on the gate's 0-100 scale
    assert verdict["maxRisk"] == 93.0 and verdict["matchedPathCount"] == 1
    assert verdict["provenance"]["basis"] == "session_scan_result" and verdict["result_id"] == "rid-1"
    assert verdict["evidenceStatus"] == "evaluated"


def test_session_deploy_decision_is_none_for_unnamed_candidate_and_ignores_suppressed():
    kwargs = dict(tenant_id="default", limit=5, warn_risk=40.0, block_risk=80.0, view="summary")
    assert session_deploy_decision(_report(), "rid-1", candidate="pillow", **kwargs) is None
    assert session_deploy_decision(_report(), "rid-1", candidate="remote", **kwargs) is None  # substrings never match
    assert session_deploy_decision(_report(suppressed=True), "rid-1", candidate="mcp-remote", **kwargs) is None


def test_session_deploy_decision_kev_from_agent_with_credential_blocks_even_below_threshold():
    report = _report(kev=True)
    report["exposure_paths"]["paths"][0]["riskScore"] = 2.0
    verdict = session_deploy_decision(
        report, "rid-1", candidate="mcp-remote", tenant_id="default", limit=5, warn_risk=40.0, block_risk=80.0, view="summary"
    )
    assert verdict["decision"] == "block" and verdict["maxRisk"] == 20.0
    assert any("KEV" in reason for reason in verdict["reasons"])


# ── tool impls ───────────────────────────────────────────────────────────────


def _run(coro):
    return json.loads(asyncio.run(coro))


def test_blast_radius_impl_reads_session_result_before_host_scan(tmp_path):
    cache = _store(tmp_path)
    rid = cache.put("local", {"report": _report()})
    calls = []

    async def _pipeline():
        calls.append("host")
        return [], [], [], []

    data = _run(
        blast_radius_impl(cve_id=CVE, _validate_cve_id=str.upper, _run_scan_pipeline=_pipeline, _truncate_response=str, _result_store=cache)
    )
    assert data["found"] is True and data["source"] == "session_scan_result" and data["result_id"] == rid
    assert calls == []


def test_blast_radius_impl_falls_through_and_reports_what_was_searched(tmp_path):
    cache = _store(tmp_path)
    rid = cache.put("local", {"report": _report()})

    async def _pipeline():
        return [], [], [], []

    data = _run(
        blast_radius_impl(
            cve_id="CVE-2020-0001", _validate_cve_id=str.upper, _run_scan_pipeline=_pipeline, _truncate_response=str, _result_store=cache
        )
    )
    assert data["error"]["code"] == "AGENTBOM_MCP_NOT_FOUND_RESOURCE"
    assert data["error"]["details"]["searched"][0] == f"session_scan_result:{rid}"
    assert "fresh scan" not in json.dumps(data)


def test_blast_radius_impl_explicit_result_id_is_authoritative(tmp_path):
    cache = _store(tmp_path)
    rid = cache.put("local", {"report": _report()})

    async def _pipeline():
        raise AssertionError("an explicit result_id never falls back to a host scan")

    missing = _run(
        blast_radius_impl(
            cve_id="CVE-2020-0001",
            result_id=rid,
            _validate_cve_id=str.upper,
            _run_scan_pipeline=_pipeline,
            _truncate_response=str,
            _result_store=cache,
        )
    )
    assert missing["error"]["code"] == "AGENTBOM_MCP_NOT_FOUND_RESOURCE" and missing["error"]["details"]["result_id"] == rid
    unknown = _run(
        blast_radius_impl(
            cve_id=CVE,
            result_id="nope",
            _validate_cve_id=str.upper,
            _run_scan_pipeline=_pipeline,
            _truncate_response=str,
            _result_store=cache,
        )
    )
    assert unknown["error"]["code"] == "AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT"


def test_deploy_decision_impl_uses_session_result_when_it_names_the_candidate(tmp_path):
    cache = _store(tmp_path)
    rid = cache.put("local", {"report": _report()})
    data = _run(deploy_decision_impl(candidate="mcp-remote@0.1.15", _truncate_response=str, _result_store=cache))
    assert data["decision"] == "block" and data["result_id"] == rid and data["provenance"]["basis"] == "session_scan_result"


def test_deploy_decision_impl_explicit_result_id_not_found_is_not_an_approval(tmp_path):
    cache = _store(tmp_path)
    rid = cache.put("local", {"report": _report()})
    data = _run(deploy_decision_impl(candidate="pillow", result_id=rid, _truncate_response=str, _result_store=cache))
    assert data["decision"] == "not_found" and data["result_id"] == rid and data["matchedPathCount"] == 0
    assert "not an approval" in " ".join(data["reasons"])


def test_exposure_paths_impl_pages_the_named_result_and_rejects_estate_filters(tmp_path):
    cache = _store(tmp_path)
    rid = cache.put("local", {"report": _report()})
    data = _run(exposure_paths_impl(result_id=rid, limit=5, _truncate_response=str, _result_store=cache))
    assert data["evidence_scope"] == "session_scan_result" and data["result_id"] == rid
    assert [path["id"] for path in data["items"]] == [PATH_ID]
    refused = _run(exposure_paths_impl(result_id=rid, limit=5, kev=True, _truncate_response=str, _result_store=cache))
    assert refused["error"]["code"] == "AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT"
    assert refused["error"]["details"]["unsupported_with_result_id"] == ["kev"]
