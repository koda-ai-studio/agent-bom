"""Context and dashboard projections preserve full evidence and tenant boundaries."""

import json

import pytest

from agent_bom.api.stores import _get_store
from agent_bom.finding_scope import safe_finding_response_payload
from tests.api.test_scan_result_sections import SECRET, _get, _put
from tests.test_api_read_contracts import empty_estate_client  # noqa: F401


@pytest.mark.parametrize(
    ("path", "context"),
    [
        ("tests/fixtures/bad.tf", "test"),
        ("examples/main.tf", "example"),
        ("docs/setup.tf", "documentation"),
        ("deploy/main.tf", "unclassified"),
        ("/home/tests/main.tf", "unclassified"),
        ("../tests/bad.tf", "unclassified"),
    ],
)
def test_context_is_safe_metadata_not_a_severity_override(path, context):
    row = {
        "finding_type": "IAC_MISCONFIGURATION",
        "source": "IAC_SCAN",
        "severity": "critical",
        "evidence": {"iac": True, "file_path": path},
    }
    safe = safe_finding_response_payload(row)
    assert safe.get("path_context") == context
    assert safe["severity"] == "critical"
    assert "file_path" not in json.dumps(safe)


def _analysis_job():
    job = _put()
    job.result["ai_inventory"] = {
        "ast_analysis": {
            "stats": {"cfg_edges": 3},
            "cfg_edges": [{"source": f"node-{i}", "target": SECRET} for i in range(3)],
            "call_graph": [],
            "dependency_symbol_reach": [],
            "findings": [{"id": "retained"}],
        }
    }
    _get_store().put(job)
    return job


def test_dashboard_omits_analysis_lists_and_preserves_full_read(empty_estate_client):  # noqa: F811
    job = _analysis_job()
    response = _get(empty_estate_client, f"/v1/scan/{job.job_id}/dashboard")
    assert response.status_code == 200
    result = response.json()["result"]
    assert "cfg_edges" not in result["ai_inventory"]["ast_analysis"]
    assert result["ai_inventory"]["ast_analysis"]["findings"] == [{"id": "retained"}]
    assert result["analysis_sections"][0]["count"] == 3
    assert result["analysis_sections"][0]["href"] == f"/v1/scan/{job.job_id}/result/ai_inventory.ast_analysis.cfg_edges?offset=0&limit=100"
    assert SECRET not in response.text
    assert _get_store().get(job.job_id, tenant_id=job.tenant_id).result == job.result
    full = _get(empty_estate_client, f"/v1/scan/{job.job_id}").json()["result"]
    assert len(full["ai_inventory"]["ast_analysis"]["cfg_edges"]) == 3
    assert _get(empty_estate_client, f"/v1/scan/{job.job_id}/dashboard", tenant="other").status_code == 404


def test_nested_analysis_is_paged_and_redacted(empty_estate_client):  # noqa: F811
    job = _analysis_job()
    path = f"/v1/scan/{job.job_id}/result/ai_inventory.ast_analysis.cfg_edges"
    response = _get(empty_estate_client, path + "?offset=1&limit=1")
    assert response.status_code == 200
    page = response.json()
    assert page["total"] == 3 and page["next_offset"] == 2
    assert page["items"][0]["source"] == "node-1"
    assert SECRET not in response.text
    assert _get(empty_estate_client, path, tenant="other").status_code == 404
    assert _get(empty_estate_client, path + "?limit=1001").status_code == 422
    assert _get(empty_estate_client, f"/v1/scan/{job.job_id}/result/ai_inventory.ast_analysis.findings").status_code == 404


def test_context_filter_precedes_grouping_and_pagination(empty_estate_client):  # noqa: F811
    job = _put()
    rows = []
    for i, path in enumerate(["deploy/main.tf", "tests/a.tf", "examples/a.tf", "tests/b.tf"]):
        rows.append(
            {
                "id": f"ctx-{i}",
                "finding_id": f"ctx-{i}",
                "finding_type": "IAC_MISCONFIGURATION",
                "source": "IAC_SCAN",
                "severity": "critical",
                "title": f"rule-{i}",
                "asset": {"name": path, "asset_type": "iac_resource"},
                "evidence": {"iac": True, "file_path": path},
            }
        )
    job.result["scan_id"] = job.job_id
    job.result["scan_run"] = {"outcome": "complete"}
    from datetime import datetime, timezone

    job.created_at = datetime.now(timezone.utc).isoformat()
    job.completed_at = job.created_at
    job.result["findings"] = rows
    job.result["blast_radius"] = []
    _get_store().put(job)
    for grouped in ("false", "true"):
        response = _get(
            empty_estate_client, f"/v1/findings?scan_id={job.job_id}&path_context=test&group_occurrences={grouped}&limit=1&sort=severity"
        )
        assert response.status_code == 200, response.text
        page = response.json()
        assert len(page["findings"]) == 1
        assert page["findings"][0]["path_context"] == "test"
        assert page["findings"][0]["severity"] == "critical"
        assert page["next_cursor"]
        next_page = _get(
            empty_estate_client,
            f"/v1/findings?scan_id={job.job_id}&path_context=test&group_occurrences={grouped}&limit=1&sort=severity&cursor={page['next_cursor']}",
        ).json()
        assert next_page["findings"][0]["path_context"] == "test"
        assert next_page["findings"][0]["id"] != page["findings"][0]["id"]
    assert _get(empty_estate_client, "/v1/findings?path_context=production").status_code == 422
    summary = _get(empty_estate_client, "/v1/findings/context-summary").json()
    assert "count" in summary, summary
    assert summary["count"] == 4
    assert {x["context"]: x["total"] for x in summary["contexts"]} == {"test": 2, "example": 1, "documentation": 0, "unclassified": 1}
    assert _get(empty_estate_client, "/v1/findings/context-summary", tenant="other").json()["count"] == 0


def test_new_views_reject_missing_credentials_when_auth_required(empty_estate_client, monkeypatch):  # noqa: F811
    from agent_bom.api.server import configure_api

    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    configure_api(api_key="test-local-context-read-key", allow_unauthenticated=False)
    try:
        assert empty_estate_client.get("/v1/findings/context-summary").status_code == 401
        assert empty_estate_client.get("/v1/scan/missing/dashboard").status_code == 401
    finally:
        configure_api(api_key=None)
