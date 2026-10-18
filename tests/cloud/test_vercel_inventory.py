"""Vercel collection must preserve scope, completeness and secret boundaries."""

import json

import httpx
import pytest

from agent_bom.cloud.vercel_inventory import collect_report

TEAM = "team_example"
PROJECT = {
    "id": "prj_example",
    "accountId": TEAM,
    "name": "test-project",
    "gitForkProtection": False,
    "link": {"type": "github", "repoId": "not-retained"},
    "ssoProtection": {"deploymentType": "all_except_custom_domains"},
    "env": [{"value": "do-not-retain"}],
    "passwordProtection": {"password": "do-not-retain"},
}
DEPLOYMENT = {
    "uid": "dpl_example",
    "projectId": "prj_example",
    "name": "test-project",
    "state": "READY",
    "target": "preview",
    "meta": {"secret": "do-not-retain"},
}


def collect(projects=None, deployments=None, status=200):
    calls = []

    def handler(request):
        calls.append(request)
        assert request.url.host == "api.vercel.com"
        assert request.url.params["teamId"] == TEAM
        assert request.method == "GET"
        key = "projects" if request.url.path == "/v10/projects" else "deployments"
        rows = (
            (projects if projects is not None else [PROJECT])
            if key == "projects"
            else (deployments if deployments is not None else [DEPLOYMENT])
        )
        return httpx.Response(status, json={key: rows, "pagination": {"next": None}})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        return collect_report(team_id=TEAM, token="test-token", client=client), calls


def test_scoped_normalization_configuration_and_no_secrets():
    report, calls = collect()
    assert len(calls) == 2
    assert report["status"] == "ok"
    assert "do-not-retain" not in json.dumps(report)
    inventory = report["cloud_inventory"][0]
    assert inventory["projects"][0]["sso_protection"] == "all_except_custom_domains"
    assert inventory["deployments"][0]["project_id"] == "prj_example"
    finding = report["findings"][0]
    assert finding["evidence"]["rule_id"] == "vercel.git_fork_protection"
    assert finding["evidence"]["rule_version"] == "1"
    assert finding["evidence"]["basis"] == "configuration"
    assert all(not c["clean_posture_assertion"] for c in report["coverage"])


def test_missing_configuration_is_unknown_not_false():
    report, _ = collect(projects=[{"id": "prj_example", "accountId": TEAM, "name": "test"}])
    assert report["findings"] == []
    assert report["configuration_checks"][0]["state"] == "unknown"


def test_no_repository_is_not_applicable():
    report, _ = collect(projects=[{**PROJECT, "link": None}])
    assert report["findings"] == []
    assert report["configuration_checks"][0]["state"] == "not_applicable"


@pytest.mark.parametrize("code,state", [(401, "unauthenticated"), (403, "denied"), (429, "rate_limited"), (500, "unavailable")])
def test_denied_collection_never_claims_empty_success(code, state):
    report, _ = collect(status=code)
    assert report["status"] == "partial"
    assert report["coverage"][0]["state"] == state
    assert not report["coverage"][0]["authenticated"]


@pytest.mark.parametrize(
    "projects,deployments",
    [
        ([{**PROJECT, "accountId": "team_other"}], None),
        ([PROJECT, 42], None),
        (None, [{**DEPLOYMENT, "projectId": "prj_other"}]),
        (None, [DEPLOYMENT, 42]),
    ],
)
def test_invalid_or_cross_scope_rows_fail_closed(projects, deployments):
    report, _ = collect(projects, deployments)
    assert report["status"] == "partial"
    assert any(c["state"] == "invalid_response" for c in report["coverage"])


def test_empty_team_is_complete_inventory_but_not_clean_posture():
    report, _ = collect([], [])
    assert report["status"] == "ok"
    assert report["findings"] == []
    assert report["reconcile_absent"] is False


def test_finding_and_asset_identity_are_stable():
    a, _ = collect()
    b, _ = collect()
    assert a["findings"][0]["id"] == b["findings"][0]["id"]
    assert a["findings"][0]["node_id"] == b["findings"][0]["node_id"]


@pytest.mark.parametrize("pagination", [{}, {"next": "https://other.invalid"}, {"next": True}])
def test_invalid_pagination_is_incomplete(pagination):
    with httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"projects": [PROJECT], "pagination": pagination}))
    ) as client:
        report = collect_report(team_id=TEAM, token="test-token", client=client)
    assert report["status"] == "partial"
    assert report["coverage"][0]["state"] == "invalid_response"


def test_repeated_cursor_is_bounded():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"projects": [PROJECT], "pagination": {"next": 100}})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        report = collect_report(team_id=TEAM, token="test-token", client=client)
    assert len(calls) == 2
    assert report["status"] == "partial"


def test_follow_pagination_and_preserve_native_scope():
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.path == "/v7/deployments":
            return httpx.Response(200, json={"deployments": [], "pagination": {"next": None}})
        next_page = "until" in request.url.params
        return httpx.Response(
            200,
            json={
                "projects": [{**PROJECT, "id": "prj_second"}] if next_page else [PROJECT],
                "pagination": {"next": None if next_page else 100},
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        report = collect_report(team_id=TEAM, token="test-token", client=client)
    assert report["status"] == "ok"
    assert len(report["cloud_inventory"][0]["projects"]) == 2
    assert len(calls) == 3


def test_invalid_requested_team_rejected_before_network():
    with pytest.raises(ValueError):
        collect_report(team_id="../other", token="test-token")


def test_graph_retains_project_deployment_and_finding_links(tmp_path):
    from agent_bom.db.graph_store import load_graph, open_graph_db, save_graph
    from agent_bom.graph.builder import build_unified_graph_from_report

    report, _ = collect()
    graph = build_unified_graph_from_report(report, scan_id="vercel-test", tenant_id="team-one")
    item = report["cloud_inventory"][0]
    ids = {item["projects"][0]["node_id"], item["deployments"][0]["node_id"], report["findings"][0]["finding_node_id"]}
    assert ids <= set(graph.nodes)
    assert any(e.source == item["projects"][0]["node_id"] and e.target == item["deployments"][0]["node_id"] for e in graph.edges)
    with open_graph_db(tmp_path / "graph.db") as conn:
        save_graph(conn, graph)
    with open_graph_db(tmp_path / "graph.db") as conn:
        loaded = load_graph(conn, tenant_id="team-one", scan_id="vercel-test")
        assert set(loaded.nodes) == set(graph.nodes)
        assert not load_graph(conn, tenant_id="team-two", scan_id="vercel-test").nodes


def test_normalizer_drops_imported_undeclared_fields():
    from agent_bom.cloud.resource_model import normalize_cloud_inventory

    report, _ = collect()
    inventory = report["cloud_inventory"][0]
    inventory["projects"][0]["password"] = "do-not-retain"
    resources = normalize_cloud_inventory(inventory)
    assert len(resources) == 2
    assert "do-not-retain" not in repr(resources)


def test_cli_persists_complete_scope_and_preserves_on_partial(tmp_path, monkeypatch):
    from click.testing import CliRunner

    import agent_bom.cloud.vercel_inventory as adapter
    from agent_bom.cli._vercel_inventory import vercel_cmd
    from agent_bom.db.graph_store import load_graph, open_graph_db

    token = tmp_path / "token.json"
    token.write_text('{"token":"test-token"}')
    token.chmod(0o600)
    output = tmp_path / "report.json"
    db = tmp_path / "graph.db"
    report, _ = collect()
    monkeypatch.setattr(adapter, "collect_report", lambda **kw: report)
    args = ["--team-id", TEAM, "--token-file", str(token), "--output", str(output), "--graph-db", str(db), "--tenant", "test"]
    result = CliRunner().invoke(vercel_cmd, args)
    assert result.exit_code == 0, result.output
    stored = json.loads(output.read_text())
    first = stored["scan_id"]
    with open_graph_db(db) as conn:
        assert load_graph(conn, tenant_id="test").scan_id == first
    assert stored["persistence"]["graph"] == "persisted"
    report, _ = collect(status=403)
    monkeypatch.setattr(adapter, "collect_report", lambda **kw: report)
    assert CliRunner().invoke(vercel_cmd, args).exit_code == 2
    with open_graph_db(db) as conn:
        assert load_graph(conn, tenant_id="test").scan_id == first
    assert json.loads(output.read_text())["persistence"]["graph"] == "skipped_incomplete"


def test_cli_rejects_credential_output_collision(tmp_path):
    from click.testing import CliRunner

    from agent_bom.cli._vercel_inventory import vercel_cmd

    token = tmp_path / "token.json"
    token.write_text('{"token":"test-token"}')
    token.chmod(0o600)
    result = CliRunner().invoke(vercel_cmd, ["--team-id", TEAM, "--token-file", str(token), "--output", str(token)])
    assert result.exit_code == 1
    assert json.loads(token.read_text()) == {"token": "test-token"}


def test_response_and_page_limits_are_incomplete(monkeypatch):
    import agent_bom.cloud.vercel_inventory as adapter

    monkeypatch.setattr(adapter, "MAX_RESPONSE_BYTES", 32)
    report, _ = collect()
    assert report["coverage"][0]["state"] == "response_limit"
    assert report["status"] == "partial"
    monkeypatch.setattr(adapter, "MAX_RESPONSE_BYTES", 2 * 1024 * 1024)
    monkeypatch.setattr(adapter, "MAX_PAGES", 1)
    with httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"projects": [PROJECT], "pagination": {"next": 100}}))
    ) as client:
        report = collect_report(team_id=TEAM, token="test-token", client=client)
    assert report["coverage"][0]["state"] == "page_limit"
    assert report["status"] == "partial"


def test_redirects_do_not_forward_credentials():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(302, headers={"Location": "https://other.invalid/projects"})

    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        report = collect_report(team_id=TEAM, token="test-token", client=client)
    assert len(requests) == 1
    assert report["status"] == "partial"


def test_import_normalizer_drops_nested_values_under_allowlisted_keys():
    from agent_bom.cloud.resource_model import normalize_vercel_inventory

    resources = normalize_vercel_inventory(
        {
            "account_id": "team_a",
            "projects": [{"id": "prj_a", "name": "fixture", "account_id": "team_a", "framework": {"secret": "never-export"}}],
        }
    )
    assert "never-export" not in str(resources)
