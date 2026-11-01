"""Executive brief uses the authenticated current-estate read contracts."""

import json
from unittest.mock import AsyncMock

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from tests import test_api_read_contracts
from tests.auth_helpers import proxy_headers

empty_estate_client = test_api_read_contracts.empty_estate_client


def test_empty_brief_is_available_without_claiming_a_passing_estate(empty_estate_client):
    response = empty_estate_client.get("/v1/brief", headers=proxy_headers())
    assert response.status_code == 200
    body = response.json()
    assert body["posture"]["no_data"] is True
    assert body["posture"]["grade"] == "N/A"
    assert body["issues"]["total"] == 0
    assert body["exposure_paths"]["paths"] == []


def test_brief_cli_uses_authenticated_client_and_returns_json(monkeypatch):
    calls = []

    class Client:
        def __init__(self, **kwargs):
            calls.append(kwargs)

        def executive_brief(self, **kwargs):
            calls.append(kwargs)
            return {"document_type": "executive-brief", "tenant_id": "brief-tenant"}

        def close(self):
            calls.append("closed")

    monkeypatch.setattr("agent_bom.cli._findings_group.AgentBomClient", Client)
    result = CliRunner().invoke(main, ["report", "brief", "--tenant", "brief-tenant", "--limit", "3", "--format", "json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["tenant_id"] == "brief-tenant"
    assert calls[0]["tenant_id"] == "brief-tenant"
    assert calls[1] == {"limit": 3}
    assert calls[-1] == "closed"


@pytest.mark.parametrize("query", ["limit=0", "limit=26", "scan_id=unimplemented-scope"])
def test_brief_rejects_unimplemented_scope_and_unbounded_limits(empty_estate_client, query):
    assert empty_estate_client.get(f"/v1/brief?{query}", headers=proxy_headers()).status_code == 422


def test_brief_mcp_tool_is_registered():
    from agent_bom.mcp_tools.catalog import registered_mcp_tool_decorator_names

    assert "executive_brief" in registered_mcp_tool_decorator_names()


def test_brief_requires_an_explicit_aggregate_read_grant():
    from agent_bom.api.route_policy import request_scopes_allow

    assert not request_scopes_allow(["posture:read"], "GET", "/v1/brief")
    assert request_scopes_allow(["brief:read"], "GET", "/v1/brief")


def test_brief_requires_authentication(empty_estate_client):
    assert empty_estate_client.get("/v1/brief").status_code in {401, 403}


@pytest.mark.asyncio
async def test_brief_preserves_canonical_sources_and_mcp_tenant(empty_estate_client, monkeypatch):
    from agent_bom.api import exec_brief
    from agent_bom.mcp_tools.brief import executive_brief_impl

    tenant = "tenant-brief"
    baseline = empty_estate_client.get("/v1/brief", headers=proxy_headers(tenant=tenant)).json()
    priorities = [
        {"vulnerability_id": "CVE-example", "asset_id": "asset-a", "owner": "team-a", "severity": "high"},
        {"vulnerability_id": "CVE-example", "asset_id": "asset-b", "owner": "team-b", "severity": "high"},
    ]
    overview = {"issue_counts": baseline["issues"], "top_risks": priorities}
    overview_reader = AsyncMock(return_value=overview)
    monkeypatch.setattr(exec_brief, "get_overview", overview_reader)
    monkeypatch.setattr(exec_brief, "get_posture_scorecard", AsyncMock(return_value=baseline["posture"]))
    monkeypatch.setattr(exec_brief, "get_compliance_summary", AsyncMock(return_value=baseline["compliance"]))
    monkeypatch.setattr(exec_brief, "get_trends", lambda *a, **kw: baseline["scan_history"])
    paths = baseline["exposure_paths"]
    paths["scan_id"] = "different-graph-snapshot"
    paths["paths"] = [{"id": "path-1", "findings": ["CVE-example"], "reachability": "unknown"}]
    path_reader = AsyncMock(return_value=json.dumps(paths))
    monkeypatch.setattr(exec_brief, "exposure_paths_for_tenant", path_reader)

    rest = empty_estate_client.get("/v1/brief?limit=2", headers=proxy_headers(tenant=tenant)).json()
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", tenant)
    mcp = json.loads(await executive_brief_impl(tenant_id="untrusted-other-tenant", limit=2))
    for body in (rest, mcp):
        assert body["tenant_id"] == tenant
        # Canonical fields pass through untouched; status and policy name are derived from them.
        assert [
            {k: v for k, v in row.items() if k not in {"sla_status", "sla_policy"}} for row in body["remediation_priorities"]
        ] == priorities
        assert all(row["sla_status"] in {"overdue", "due_soon", "on_track", "unknown"} for row in body["remediation_priorities"])
        assert "owner" not in body["exposure_paths"]["paths"][0]
        assert body["exposure_paths"] == paths
        assert body["scan_history"] == baseline["scan_history"]
        assert "delta" not in body["posture"]
        assert body["scope"]["exposure_scan_id"] == "different-graph-snapshot"
        assert body["scope"]["consistency"] == "independent_source_reads"
    assert all(call.args[0].state.tenant_id == tenant for call in overview_reader.call_args_list)
    assert all(call.kwargs == {"tenant_id": tenant, "limit": 2, "view": "summary"} for call in path_reader.call_args_list)


def test_unavailable_graph_is_not_an_empty_clean_graph(empty_estate_client, monkeypatch):
    monkeypatch.setattr("agent_bom.api.exec_brief.exposure_paths_for_tenant", AsyncMock(return_value='{"error":{"code":"unavailable"}}'))
    body = empty_estate_client.get("/v1/brief", headers=proxy_headers()).json()
    assert body["exposure_status"] == "unavailable"
    assert body["exposure_paths"] is None
    from agent_bom.cli._brief import render_markdown

    rendered = render_markdown(body)
    assert "Path evidence unavailable" in rendered
    assert "No paths returned" not in rendered


def test_markdown_escapes_untrusted_labels(empty_estate_client):
    from agent_bom.cli._brief import render_markdown

    body = empty_estate_client.get("/v1/brief", headers=proxy_headers()).json()
    body["remediation_priorities"] = [
        {"vulnerability_id": "<script>alert(1)</script>|\n# injected", "owner": "[owner](https://example.com)"}
    ]
    rendered = render_markdown(body)
    assert "<script>" not in rendered
    assert "\n# injected" not in rendered
    assert "[owner](https://example.com)" not in rendered


def test_python_client_preserves_auth_and_scope():
    import httpx

    from agent_bom.client import AgentBomClient

    captured = []

    def handler(request):
        captured.append(request)
        return httpx.Response(200, json={"document_type": "executive-brief"})

    with AgentBomClient(
        base_url="https://example.com", api_key="test-key", tenant_id="tenant-brief", transport=httpx.MockTransport(handler)
    ) as client:
        assert client.executive_brief(limit=3)["document_type"] == "executive-brief"
    assert str(captured[0].url) == "https://example.com/v1/brief?limit=3"
    assert captured[0].headers["X-API-Key"] == "test-key"
    assert captured[0].headers["X-Agent-Bom-Tenant-ID"] == "tenant-brief"


def test_demo_brief_is_labelled_sample_data(demo_estate_client):
    from agent_bom.cli._brief import render_markdown

    response = demo_estate_client.get("/v1/brief")
    assert response.status_code == 200
    body = response.json()
    assert body.get("sample_data") is True
    assert "Sample data" in render_markdown(body)


def test_markdown_uses_exposure_endpoints_and_readable_coverage(empty_estate_client):
    from agent_bom.cli._brief import render_markdown

    body = empty_estate_client.get("/v1/brief", headers=proxy_headers()).json()
    body["exposure_paths"] = {
        "scan_id": "snapshot-1",
        "snapshot_generation": "generation-1",
        "paths": [{"source": {"label": "Data Pipeline"}, "target": {"label": "CVE-example"}, "severity": "high", "reachability": "likely"}],
        "collection_coverage": {"status": "unknown", "reason": "Source collection not established."},
        "completeness": {"status": "truncated", "returned": 1, "total": 50, "reason": "path_page_limit"},
    }
    rendered = render_markdown(body)
    assert "Data Pipeline → CVE-example" in rendered
    assert "Collection coverage: unknown" in rendered
    assert "Paths returned: 1 of 50 · Completeness: truncated" in rendered
    assert "Source collection not established." in rendered
