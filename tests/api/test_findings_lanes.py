"""Finding lanes share one server predicate and preserve occurrence evidence."""

from agent_bom.api.finding_grouping import _group_occurrence_rows, cloud_control_severity_counts, select_group_lane
from agent_bom.finding import Asset, Finding, FindingSource, FindingType, cloud_cis_check_to_finding, iac_finding_to_finding
from agent_bom.finding_scope import row_matches_scope


def cloud(resource, provider="aws", control="1.4"):
    return cloud_cis_check_to_finding(
        {"check_id": control, "title": "Restrict admin access", "severity": "high", "resource_ids": [resource]}, provider
    ).to_dict()


def test_lanes_separate_iac_cloud_and_unknown_without_title_guessing():
    iac = iac_finding_to_finding({"rule_id": "K8S-RBAC-005", "file_path": "main.tf", "repository_relative_path": "infra/main.tf"}).to_dict()
    rows = [(cloud("role-1"), "cloud"), (iac, "iac")]
    for kind, lane in [
        (FindingType.CVE, "vulnerabilities"),
        (FindingType.CREDENTIAL_EXPOSURE, "secrets"),
        (FindingType.CIEM_OVER_PRIVILEGE, "identity"),
        (FindingType.SENSITIVE_DATA, "data"),
        (FindingType.PROMPT_SECURITY, "other"),
    ]:
        rows.append((Finding(kind, FindingSource.MCP_SCAN, Asset("example", "agent"), "high").to_dict(), lane))
    for row, expected in rows:
        assert row["lane"] == expected
        for lane in ("cloud", "iac", "vulnerabilities", "secrets", "identity", "data", "other"):
            assert row_matches_scope(row, {"lane": lane}) is (lane == expected)
    assert not row_matches_scope(cloud("role"), {"lane": "unknown"})
    imported = {**cloud("role"), "finding_type": " cis_fail ", "lane": "identity"}
    assert row_matches_scope(imported, {"lane": "cloud"})


def test_cloud_groups_are_control_and_provider_scoped():
    rows = [cloud("role-1"), cloud("role-2"), cloud("role-3", "azure"), cloud("role-4", control="1.5")]
    assert len(_group_occurrence_rows(rows)) == 4
    groups = _group_occurrence_rows(rows, cloud_controls=True)
    assert len(groups) == 3
    assert groups[0]["occurrence_count"] == 2
    assert {r["asset"]["name"] for r in groups[0]["_occurrence_rows"]} == {"role-1", "role-2"}


def test_severity_source_and_cis_title_are_explicit():
    row = cloud("role-1")
    assert row["severity_source"] == "benchmark-mapped"
    assert row["title"] == "Failed CIS 1.4 — Restrict admin access"
    original = Finding(FindingType.CVE, FindingSource.MCP_SCAN, Asset("package", "package"), "high", severity_source="cvss")
    assert original.to_dict()["severity_source"] == "cvss"


def test_api_lanes_filter_before_pagination_and_counts_reconcile(monkeypatch, tmp_path):
    from starlette.testclient import TestClient

    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.server import app, set_job_store
    from agent_bom.api.store import InMemoryJobStore
    from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

    enable_trusted_proxy_env()
    store = InMemoryJobStore()
    set_job_store(store)
    try:
        job = ScanJob(job_id="lane-scan", tenant_id="lane-test", created_at="2026-10-19T12:00:00Z", request=ScanRequest())
        job.status = JobStatus.DONE
        job.completed_at = job.created_at
        job.result = {
            "findings": [
                cloud("role-1"),
                cloud("role-2"),
                cloud("role-3", control="1.5"),
                iac_finding_to_finding({"rule_id": "TF-1", "file_path": "main.tf"}).to_dict(),
            ]
        }
        store.put(job)
        client = TestClient(app)
        headers = proxy_headers(role="analyst", tenant="lane-test")
        query = {"lane": " CLOUD ", "group_occurrences": True, "include_facets": True, "window_days": 0, "limit": 1}
        page = client.get("/v1/findings", params=query, headers=headers)
        assert page.status_code == 200, page.text
        body = page.json()
        assert body["total"] == 2
        assert body["facets"]["lane"]["cloud"] == 3
        assert body["grouping"]["unit"] == "control_groups"
        assert body["grouping"]["canonical_issue_total"] == 3
        all_page = client.get("/v1/findings", params={**query, "lane": "", "limit": 100}, headers=headers).json()
        assert all_page["total"] == 4
        assert sum(all_page["facets"]["lane"].values()) == all_page["total"]
        assert body["facets"]["lane"]["iac"] == 1
        assert body["findings"][0]["severity_source"] == "benchmark-mapped"
        assert body["findings"][0]["lane"] == "cloud"
        assert body["next_cursor"]
        second = client.get("/v1/findings", params={**query, "cursor": body["next_cursor"]}, headers=headers).json()
        assert second["findings"][0]["finding_group_id"] != body["findings"][0]["finding_group_id"]
        assert not second["has_more"]
        raw = client.get("/v1/findings", params={"lane": "iac", "window_days": 0}, headers=headers).json()
        assert raw["total"] == 1
        assert raw["findings"][0]["lane"] == "iac"
        assert raw["findings"][0]["source"] == "IAC_SCAN"
        import asyncio
        import gzip
        import json

        from agent_bom.api.report_worker import _run_report_job_sync
        from agent_bom.mcp_tools.findings import findings_query_impl

        monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "lane-test")
        tool = json.loads(asyncio.run(findings_query_impl(lane="iac", window_days=0)))
        assert tool["count"] == 1
        assert tool["findings"][0]["lane"] == "iac"
        assert tool["findings"][0]["severity_source"] == "rule"
        monkeypatch.setenv("AGENT_BOM_REPORT_ARTIFACT_DIR", str(tmp_path))
        monkeypatch.setattr("agent_bom.api.routes.reports.submit_report_job", _run_report_job_sync)
        created = client.post("/v1/reports", json={"lane": "iac", "window_days": 0}, headers=headers)
        assert created.status_code == 202, created.text
        report = client.get(f"/v1/reports/{created.json()['job_id']}", headers=headers).json()
        assert report["status"] == "done", report
        assert report["row_count"] == 1
        exported = client.get(report["download_url"], headers={**headers, "X-Agent-Bom-Download-Token": report["download_token"]})
        exported_rows = [json.loads(line) for line in gzip.decompress(exported.content).decode().splitlines()]
        assert exported_rows[0]["lane"] == "iac"
        assert exported_rows[0]["severity_source"] == "rule"
        wrong_tenant = client.get("/v1/findings", params=query, headers=proxy_headers(role="analyst", tenant="another")).json()
        assert wrong_tenant["total"] == 0
    finally:
        disable_trusted_proxy_env()
        set_job_store(InMemoryJobStore())


def test_iac_source_retains_its_graph_collector():
    from agent_bom.graph.finding_row_projection import _collector

    row = iac_finding_to_finding({"rule_id": "TF-1", "file_path": "main.tf"}).to_dict()
    assert _collector(row) == ("iac", "static_scan")


def test_cloud_control_group_keeps_worst_severity_and_filtered_occurrences():
    low, high = cloud("role-low"), cloud("role-high")
    low["severity"] = "low"
    facets = cloud_control_severity_counts([low, high])
    assert facets["high"] == facets["low"] == 1
    groups = _group_occurrence_rows([low, high])
    selected, _, counts = select_group_lane(groups, None, "cloud")
    assert selected[0]["severity"] == "high"
    assert selected[0]["occurrence_count"] == 2
    assert counts["cloud"] == 2
    selected, _, counts = select_group_lane(groups, "low", "cloud")
    assert selected[0]["severity"] == "low"
    assert selected[0]["occurrence_count"] == 1
    assert counts["cloud"] == 1
