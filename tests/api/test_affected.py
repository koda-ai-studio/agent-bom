"""``/v1/affected`` answers "am I affected?" from the same current queue as /v1/findings."""

from __future__ import annotations

from unittest.mock import Mock

import pytest
from starlette.testclient import TestClient

from agent_bom.api import affected_read
from agent_bom.api.affected_read import parse_query
from agent_bom.api.server import app
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from tests.api.test_scan_job_sla_history import job
from tests.api.test_scan_job_sla_history import scan_store as history_store  # noqa: F401
from tests.auth_helpers import proxy_headers


@pytest.fixture
def scan_store(history_store):  # noqa: F811 - imported parametrized fixture
    return history_store


def _finding(cve: str, package: str, version: str = "1.0.0", **extra: object) -> Finding:
    return Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name=package, asset_type="package", identifier=f"pkg:pypi/{package}@{version}"),
        severity="critical",
        cve_id=cve,
        title=f"{cve}: {package}@{version}",
        evidence={"package_name": package, "package_version": version},
        **extra,  # type: ignore[arg-type]
    )


def _affected(q: str) -> dict:
    with TestClient(app) as client:
        client.headers.update(proxy_headers(role="analyst", tenant="history-tenant"))
        response = client.get("/v1/affected", params={"q": q})
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CVE-2024-3094", {"kind": "advisory", "advisory": "CVE-2024-3094"}),
        ("ghsa-jfh8-c2jp-5v3q", {"kind": "advisory", "advisory": "GHSA-JFH8-C2JP-5V3Q"}),
        ("pillow", {"kind": "package", "package": "pillow", "version": None}),
        ("Pillow@9.0.0", {"kind": "package", "package": "pillow", "version": "9.0.0"}),
        ("@scope/pkg@1.2.3", {"kind": "package", "package": "@scope/pkg", "version": "1.2.3"}),
    ],
)
def test_queries_are_advisories_or_packages(raw: str, expected: dict) -> None:
    assert {key: parse_query(raw).get(key) for key in expected} == expected


def test_an_open_advisory_is_affected_with_its_window_assets_and_fix_state(scan_store) -> None:
    scan_store.put(job(9, findings=[_finding("CVE-2026-1111", "left-pad", fixed_version="1.0.1"), _finding("CVE-2026-2222", "right-pad")]))
    body = _affected("cve-2026-1111")
    assert body["verdict"] == "affected"
    assert body["query"] == {"raw": "cve-2026-1111", "kind": "advisory", "advisory": "CVE-2026-1111", "package": None, "version": None}
    assert body["findings"]["total"] == 1 and body["findings"]["open"] == 1
    assert body["findings"]["fix_available"] == 1 and body["findings"]["no_fix"] == 0
    assert body["exposure"]["still_open"] is True and body["exposure"]["first_seen"].startswith("2026-09-01")
    assert [asset["package"] for asset in body["assets"]] == ["left-pad"]
    assert body["findings_href"] == "/findings?q=CVE-2026-1111&status=all"


def test_a_package_query_matches_the_package_and_version_exactly(scan_store) -> None:
    scan_store.put(job(9, findings=[_finding("CVE-2026-1111", "left-pad"), _finding("CVE-2026-3333", "left-pad-extra")]))
    assert _affected("left-pad")["findings"]["advisories"] == ["CVE-2026-1111"]
    assert _affected("left-pad@1.0.0")["verdict"] == "affected"
    assert _affected("left-pad@2.0.0")["verdict"] == "not_found"


def test_a_resolved_finding_is_previously_affected_and_unknown_is_not_found(scan_store) -> None:
    scan_store.put(job(8, findings=[_finding("CVE-2026-1111", "left-pad")]))
    scan_store.put(job(9, findings=[]))
    body = _affected("CVE-2026-1111")
    assert body["verdict"] == "previously_affected"
    assert body["exposure"]["still_open"] is False and body["findings"]["resolved"] == 1
    assert _affected("CVE-2099-0001")["verdict"] == "not_found"


def test_reach_merges_the_story_groups_of_matched_advisories(scan_store, monkeypatch) -> None:
    scan_store.put(job(9, findings=[_finding("CVE-2026-1111", "left-pad")]))

    graph_store = Mock()
    graph_store.snapshot_identity.return_value = ("snap-1", "generation-1")
    monkeypatch.setattr("agent_bom.api.stores._get_graph_store", lambda: graph_store)

    def story(_store, *, tenant_id, scan_id, node_id, **_kwargs):
        assert node_id == "vuln:CVE-2026-1111" and tenant_id == "history-tenant"
        items = [{"id": "cred:token", "label": "TOKEN", "entity_type": "credential"}]
        return {
            "scan_id": "snap-1",
            "snapshot_generation": "generation-1",
            "at_risk": {"groups": [{"kind": "credentials", "items": items}], "listed_complete": True, "completeness": {"complete": True}},
        }

    monkeypatch.setattr("agent_bom.graph.exploit_story_read.read_exploit_story", story)
    reach = _affected("CVE-2026-1111")["reach"]
    assert reach["basis"] == "graph_snapshot" and reach["scan_id"] == "snap-1"
    assert reach["by_kind"] == {"credentials": 1} and reach["items"]["credentials"][0]["label"] == "TOKEN"
    assert reach["advisories_walked"] == ["CVE-2026-1111"]


def test_reach_is_bounded_and_says_so(scan_store, monkeypatch) -> None:
    monkeypatch.setattr(affected_read, "MAX_STORIES", 1)
    findings = [_finding(f"CVE-2026-{index}000", "left-pad") for index in range(1, 4)]
    scan_store.put(job(9, findings=findings))
    reach = _affected("left-pad")["reach"]
    assert "first 1 of 3" in str(reach["note"])


def test_the_mcp_tool_returns_the_rest_answer(scan_store, monkeypatch) -> None:
    import asyncio
    import json

    from agent_bom.mcp_tools.affected import am_i_affected_impl

    # MCP tools read the server-bound tenant, never one a tool call supplies.
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "history-tenant")

    scan_store.put(job(9, findings=[_finding("CVE-2026-1111", "left-pad")]))
    body = json.loads(asyncio.run(am_i_affected_impl(q="CVE-2026-1111", tenant_id="history-tenant")))
    assert body["tool"] == "am_i_affected" and body["verdict"] == "affected" and body["findings"]["total"] == 1
    assert "error" in json.loads(asyncio.run(am_i_affected_impl(q=" ", tenant_id="history-tenant")))


def test_the_cli_leads_with_the_verdict(monkeypatch) -> None:
    from click.testing import CliRunner

    from agent_bom.cli._findings_group import findings_cmd

    payload = {
        "verdict": "affected",
        "query": {"raw": "CVE-2026-1111"},
        "findings": {"total": 2, "open": 1, "resolved": 1, "kev": True, "fix_available": 1, "no_fix": 1},
        "exposure": {"first_seen": "2026-08-01", "last_seen": "2026-09-01"},
        "assets": [{"name": "left-pad", "version": "1.0.0", "status": "open", "advisory": "CVE-2026-1111"}],
        "reach": {"by_kind": {"credentials": 2}},
    }
    monkeypatch.setattr("agent_bom.client.AgentBomClient.affected", lambda self, query: payload)
    result = CliRunner().invoke(findings_cmd, ["affected", "CVE-2026-1111", "--api-url", "http://127.0.0.1:1"])
    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    assert lines[0] == "AFFECTED: CVE-2026-1111"
    assert "KEV: yes" in result.output and "2 credentials" in result.output and "left-pad 1.0.0 [open]" in result.output


@pytest.mark.parametrize(("summary", "verdict"), [({"affected": 2}, "affected"), ({"possibly_affected": 1}, "possibly_affected")])
def test_an_inventory_match_without_a_finding_still_answers(scan_store, monkeypatch, summary, verdict) -> None:
    """A new advisory matched against stored inventory is affected before any scan turns it into a finding."""
    answer = {
        "summary": {"affected": 0, "possibly_affected": 0, "not_affected": 0, "assets_examined": 3, **summary},
        "complete": True,
        "advisory": {"source": "feed"},
    }
    monkeypatch.setattr("agent_bom.api.advisory_affected_read.tenant_affected_answer", lambda tenant, advisory: answer)
    body = _affected("CVE-2026-7777")
    assert body["verdict"] == verdict and body["verdict_basis"] == ["inventory_match"]
    assert body["findings"]["total"] == 0 and body["inventory"]["href"] == "/v1/intel/advisories/CVE-2026-7777/affected"
