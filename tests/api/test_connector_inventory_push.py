"""Vercel and Supabase inventory joins the served current estate through the push path."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores
from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.models import PushPayload
from agent_bom.api.push_evidence import normalize_pushed_report
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.cloud.connector_push import connector_push_payloads
from agent_bom.push import sanitize_results
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers
from tests.cloud import test_supabase_inventory as supabase_fixture
from tests.cloud import test_vercel_inventory as vercel_fixture

TENANT = "connector-tenant"
SCAN = {
    "source_id": "laptop-one",
    "target_scope": "v1:" + "a" * 64,
    "agents": [
        {
            "name": "desk-agent",
            "type": "claude-desktop",
            "mcp_servers": [{"name": "files", "command": "npx", "args": [], "packages": []}],
        }
    ],
}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("agent_bom.api.campaign_reconciliation.poll_campaign_reconciliation", lambda: None)
    original_jobs, original_graph = stores._store, stores._graph_store
    stores.set_job_store(InMemoryJobStore())
    monkeypatch.setattr(stores, "_graph_store", SQLiteGraphStore(str(tmp_path / "graph.db")))
    set_compliance_hub_store(InMemoryComplianceHubStore())
    enable_trusted_proxy_env()
    with TestClient(app) as test_client:
        yield test_client
    stores.set_job_store(original_jobs)
    stores._graph_store = original_graph
    set_compliance_hub_store(None)
    disable_trusted_proxy_env()


def vercel_report(projects=None, status=200, deployments=None):
    report, _ = vercel_fixture.collect(projects=projects, deployments=deployments, status=status)
    return report


def supabase_report(refs=(supabase_fixture.REF,)):
    report, _ = supabase_fixture.collect(refs=refs)
    return report


def push(client, payload, tenant=TENANT):
    # The real CLI path: client-side redaction, then the HTTP push route.
    response = client.post(
        "/v1/results/push",
        json=sanitize_results(payload, source_id=payload["source_id"]),
        headers=proxy_headers(role="analyst", tenant=tenant),
    )
    assert response.status_code == 201, response.text
    return response.json()


def push_connector(client, report, tenant=TENANT):
    return [push(client, payload, tenant) for payload in connector_push_payloads(report)]


def graph(client, tenant=TENANT):
    response = client.get("/v1/graph", params={"limit": 5000}, headers=proxy_headers(role="viewer", tenant=tenant))
    return response


def node_ids(client, tenant=TENANT):
    response = graph(client, tenant)
    assert response.status_code == 200, response.text
    return {node["id"] for node in response.json()["nodes"]}


def vercel_project_node(name="prj_example"):
    from agent_bom.cloud.vercel_model import node_id

    return node_id(vercel_fixture.TEAM, "project", name)


def test_payloads_carry_connector_identity_and_scoped_replacement():
    [vercel] = connector_push_payloads(vercel_report())
    assert vercel["source_id"] == f"connector:vercel:{vercel_fixture.TEAM}"
    assert vercel["target_scope"].startswith("v1:")
    assert vercel["scan_run"]["outcome"] == "complete"
    report = supabase_report(refs=(supabase_fixture.REF, supabase_fixture.OTHER))
    payloads = connector_push_payloads(report)
    assert [p["source_id"] for p in payloads] == [
        f"connector:supabase:{supabase_fixture.REF}",
        f"connector:supabase:{supabase_fixture.OTHER}",
    ]
    assert len({p["target_scope"] for p in payloads}) == 2
    report["scan_id"] = "one-local-run"
    payloads = connector_push_payloads(report)
    for payload in payloads:
        # A shared local scan id would make per-project graph snapshots collide.
        assert "scan_id" not in payload
        ref = payload["source_id"].rsplit(":", 1)[1]
        assert {c["project_ref"] for c in payload["coverage"]} == {ref}
        assert {f["evidence"]["project_ref"] for f in payload["findings"]} == {ref}
        assert [p["ref"] for inv in payload["cloud_inventory"] for p in inv["projects"]] == [ref]


def test_normalized_push_retains_inventory_findings_and_receipts():
    [payload] = connector_push_payloads(vercel_report())
    body = PushPayload.model_validate(sanitize_results(payload, source_id=payload["source_id"]))
    report = normalize_pushed_report(body, fallback_scan_id="fallback")
    assert report["cloud_inventory"] == payload["cloud_inventory"]
    assert report["coverage"] == payload["coverage"]
    assert all(receipt["authenticated"] is True for receipt in report["coverage"])
    assert report["findings"][0]["evidence"]["rule_id"] == "vercel.git_fork_protection"
    assert report["replacement_scope_status"] == "identified"
    assert report["scan_run"]["outcome"] == "complete"
    assert report["summary"]["total_findings"] == 1


def test_connector_inventory_joins_current_estate_alongside_a_scan(client):
    push(client, SCAN)
    push_connector(client, vercel_report())
    push_connector(client, supabase_report())
    nodes = node_ids(client)
    from agent_bom.cloud.resource_model import supabase_project_node_id

    assert vercel_project_node() in nodes
    assert f"account:vercel:{vercel_fixture.TEAM}" in nodes
    assert supabase_project_node_id("org-one", supabase_fixture.REF) in nodes
    assert any(node.startswith("agent:") for node in nodes), nodes
    body = graph(client).json()
    vercel_nodes = [n for n in body["nodes"] if n["id"] == vercel_project_node()]
    assert vercel_nodes[0]["attributes"]["account_id"] == vercel_fixture.TEAM


def test_second_push_for_same_team_replaces_only_that_scope(client):
    from agent_bom.cloud.resource_model import supabase_project_node_id

    push(client, SCAN)
    push_connector(client, vercel_report())
    push_connector(client, supabase_report())
    push_connector(client, vercel_report(projects=[{**vercel_fixture.PROJECT, "id": "prj_second"}], deployments=[]))
    nodes = node_ids(client)
    assert vercel_project_node("prj_second") in nodes
    assert vercel_project_node() not in nodes
    assert supabase_project_node_id("org-one", supabase_fixture.REF) in nodes
    assert any(node.startswith("agent:") for node in nodes)


def test_partial_inventory_is_marked_partial_and_keeps_prior_assets(client):
    push_connector(client, vercel_report())
    [receipt] = push_connector(client, vercel_report(status=403))
    assert receipt["scan_outcome"] == "partial"
    assert receipt["source_id"] == f"connector:vercel:{vercel_fixture.TEAM}"
    assert receipt["replacement_scope_status"] == "identified"
    response = graph(client)
    assert vercel_project_node() in {node["id"] for node in response.json()["nodes"]}
    assert response.json()["collection_coverage"]["status"] == "partial"


def test_connector_inventory_is_tenant_isolated(client):
    push_connector(client, vercel_report())
    push(client, SCAN, tenant="other-tenant")
    assert vercel_project_node() in node_ids(client)
    assert vercel_project_node() not in node_ids(client, tenant="other-tenant")


def _token(tmp_path):
    token = tmp_path / "token.json"
    token.write_text('{"token":"test-token"}')
    token.chmod(0o600)
    return token


def _route_push_to(client, monkeypatch, calls):
    def push_json(url, payload, api_key=None, *, source_id=None):
        calls.append((url, api_key, source_id))
        response = client.post(
            "/v1/results/push", json=sanitize_results(payload, source_id=source_id), headers=proxy_headers(role="analyst", tenant=TENANT)
        )
        return response.json() if response.status_code == 201 else None

    monkeypatch.setattr("agent_bom.push.push_json", push_json)


def _vercel_args(token, output, url="http://127.0.0.1:8422"):
    return ["vercel", "--team-id", vercel_fixture.TEAM, "--token-file", str(token), "--output", str(output), "--push-url", url]


def test_cli_push_url_lands_vercel_and_supabase_in_current_estate(client, tmp_path, monkeypatch):
    import json

    from click.testing import CliRunner

    import agent_bom.cloud.supabase_inventory as supabase_adapter
    import agent_bom.cloud.vercel_inventory as vercel_adapter
    from agent_bom.cli._cloud_group import cloud_group
    from agent_bom.cloud.resource_model import supabase_project_node_id

    calls: list = []
    _route_push_to(client, monkeypatch, calls)
    monkeypatch.setenv("AGENT_BOM_PUSH_API_KEY", "push-key")
    token = _token(tmp_path)
    vercel = vercel_report()
    monkeypatch.setattr(vercel_adapter, "collect_report", lambda **kw: vercel)
    output = tmp_path / "vercel.json"
    result = CliRunner().invoke(cloud_group, _vercel_args(token, output))
    assert result.exit_code == 0, result.output
    stored = json.loads(output.read_text())
    assert stored["persistence"]["push"]["status"] == "pushed"
    assert stored["persistence"]["push"]["receipts"][0]["source_id"] == f"connector:vercel:{vercel_fixture.TEAM}"
    assert stored["persistence"]["graph"] == "not_requested"
    assert calls == [("http://127.0.0.1:8422/v1/results/push", "push-key", f"connector:vercel:{vercel_fixture.TEAM}")]

    refs = (supabase_fixture.REF, supabase_fixture.OTHER)
    supabase = supabase_report(refs=refs)
    monkeypatch.setattr(supabase_adapter, "collect_report", lambda **kw: supabase)
    output = tmp_path / "supabase.json"
    args = ["supabase", "--token-file", str(token), "--output", str(output), "--push-url", "http://127.0.0.1:8422"]
    for ref in refs:
        args += ["--project-ref", ref]
    result = CliRunner().invoke(cloud_group, args)
    assert result.exit_code == 0, result.output
    assert [c[2] for c in calls[1:]] == [f"connector:supabase:{ref}" for ref in refs]
    nodes = node_ids(client)
    assert vercel_project_node() in nodes
    assert {supabase_project_node_id("org-one", ref) for ref in refs} <= nodes


def test_cli_pushes_partial_inventory_as_partial_and_exits_2(client, tmp_path, monkeypatch):
    import json

    from click.testing import CliRunner

    import agent_bom.cloud.vercel_inventory as vercel_adapter
    from agent_bom.cli._cloud_group import cloud_group

    _route_push_to(client, monkeypatch, [])
    token = _token(tmp_path)
    output = tmp_path / "vercel.json"
    for report, code in ((vercel_report(), 0), (vercel_report(status=403), 2)):
        monkeypatch.setattr(vercel_adapter, "collect_report", lambda report=report, **kw: report)
        assert CliRunner().invoke(cloud_group, _vercel_args(token, output)).exit_code == code
    stored = json.loads(output.read_text())
    assert stored["persistence"]["push"]["receipts"][0]["scan_outcome"] == "partial"
    response = graph(client)
    assert vercel_project_node() in {node["id"] for node in response.json()["nodes"]}
    assert response.json()["collection_coverage"]["status"] == "partial"


def test_cli_push_failure_is_recorded_and_fails(tmp_path, monkeypatch):
    import json

    from click.testing import CliRunner

    import agent_bom.cloud.vercel_inventory as vercel_adapter
    from agent_bom.cli._cloud_group import cloud_group

    monkeypatch.setattr("agent_bom.push.push_json", lambda *a, **kw: None)
    report = vercel_report()
    monkeypatch.setattr(vercel_adapter, "collect_report", lambda **kw: report)
    output = tmp_path / "vercel.json"
    result = CliRunner().invoke(cloud_group, _vercel_args(_token(tmp_path), output, "https://cp.example"))
    assert result.exit_code == 1
    assert "test-token" not in result.output
    assert json.loads(output.read_text())["persistence"]["push"]["status"] == "failed"
