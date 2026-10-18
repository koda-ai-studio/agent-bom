"""Scoped management reads must retain unknown posture and native evidence."""

from __future__ import annotations

import json

import httpx
import pytest

from agent_bom.cloud.supabase_inventory import collect_report

REF = "abcdefghijklmnopqrst"
OTHER = "bcdefghijklmnopqrstu"


def project(ref=REF, status="ACTIVE_HEALTHY"):
    return {
        "id": ref,
        "ref": ref,
        "organization_id": "org-one",
        "name": "demo",
        "region": "us-east-2",
        "status": status,
        "database": {"version": "17.6", "password": "never-store-this"},
        "api_key": "never-store-this",
    }


def lint(level="ERROR"):
    return {
        "name": "rls_disabled_in_public",
        "cache_key": "table-public-example",
        "title": "RLS disabled",
        "level": level,
        "categories": ["SECURITY"],
        "observed_at": "2026-10-17T12:00:00Z",
        "metadata": {"schema": "public", "name": "example", "type": "table", "secret": "never-store-this"},
        "detail": "never-store-this",
        "remediation": "https://supabase.com/docs/guides/database/database-linter",
    }


def collect(payload=None, advisors=None, advisor_status=200, refs=(REF,)):
    calls = []

    def handler(request):
        calls.append(request)
        assert request.method == "GET"
        assert request.url.host == "api.supabase.com"
        assert request.headers["Authorization"] == "Bearer test-token"
        if request.url.path.endswith("/advisors/security"):
            return httpx.Response(advisor_status, json=advisors if advisors is not None else {"lints": [lint()]})
        return httpx.Response(200, json=payload if payload is not None else project(request.url.path.rsplit("/", 1)[1]))

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        report = collect_report(project_refs=list(refs), token="test-token", client=client)
    return report, calls


def test_scoped_allowlisted_read_and_native_finding():
    report, calls = collect()
    assert len(calls) == 2
    assert report["status"] == "ok"
    assert "never-store-this" not in json.dumps(report)
    finding = report["findings"][0]
    assert finding["evidence"]["native_severity"] == "ERROR"
    assert finding["severity"] == "high"
    assert finding["evidence"]["native_id"] == "table-public-example"
    assert finding["evidence"]["source_observed_at"] == "2026-10-17T12:00:00Z"
    assert finding["evidence"]["rule_version"] is None
    assert finding["node_id"]


def test_paused_empty_is_unknown_not_clean():
    report, _ = collect(payload=project(status="INACTIVE"), advisors={"lints": []})
    assert report["status"] == "partial"
    assert report["coverage"][1]["state"] == "paused"
    assert report["coverage"][1]["read"] is True
    assert report["coverage"][1]["evaluated"] is False
    assert report["findings"] == []
    assert len(report["cloud_inventory"][0]["projects"]) == 1


def test_empty_active_is_scoped_empty_not_clean():
    report, _ = collect(advisors={"lints": []})
    assert report["status"] == "ok"
    assert report["coverage"][1]["state"] == "empty"
    assert report["coverage"][1]["clean_posture_assertion"] is False


@pytest.mark.parametrize("payload", [{}, {"lints": None}, {"lints": [{}]}, {"lints": [lint(), 42]}])
def test_malformed_advisors_are_partial_without_partial_findings(payload):
    report, _ = collect(advisors=payload)
    assert report["status"] == "partial"
    assert report["coverage"][1]["state"] == "invalid_response"
    assert not report["findings"]


@pytest.mark.parametrize("code,state", [(401, "unauthenticated"), (403, "denied"), (429, "rate_limited"), (500, "unavailable")])
def test_advisor_failure_preserves_inventory_and_coverage(code, state):
    report, _ = collect(advisors={"error": "never-store-this"}, advisor_status=code)
    assert report["coverage"][1]["state"] == state
    assert report["coverage"][1]["authenticated"] is False
    assert report["status"] == "partial"
    assert report["cloud_inventory"][0]["projects"]
    assert "never-store-this" not in json.dumps(report)


def test_returned_project_must_match_requested_scope():
    report, calls = collect(payload=project(OTHER))
    assert len(calls) == 1
    assert report["status"] == "partial"
    assert not report["cloud_inventory"]
    assert report["coverage"][0]["state"] == "invalid_response"


@pytest.mark.parametrize("refs", [[], ["../secrets"], ["https://other.example"], ["a" * 21]])
def test_invalid_scope_rejected_before_network(refs):
    with pytest.raises(ValueError):
        collect(refs=refs)


def test_replay_and_distinct_project_finding_ids():
    one, _ = collect(refs=(REF, OTHER, REF))
    two, _ = collect(refs=(REF, OTHER))
    assert len(one["findings"]) == 2
    assert len({f["id"] for f in one["findings"]}) == 2
    assert [f["id"] for f in one["findings"]] == [f["id"] for f in two["findings"]]


def test_unknown_level_stays_unknown():
    report, _ = collect(advisors={"lints": [lint("NEW_LEVEL")]})
    assert report["findings"][0]["severity"] == "unknown"
    assert report["findings"][0]["evidence"]["native_severity"] == "NEW_LEVEL"


def test_graph_persists_native_finding_links_across_restart_and_tenant(tmp_path):
    from agent_bom.db.graph_store import load_graph, open_graph_db, save_graph
    from agent_bom.graph.builder import build_unified_graph_from_report

    report, _ = collect()
    graph = build_unified_graph_from_report(report, scan_id="supabase-test", tenant_id="one")
    finding = report["findings"][0]
    assert finding["node_id"] in graph.nodes
    assert finding["finding_node_id"] in graph.nodes
    assert any(e.source == finding["finding_node_id"] and e.target == finding["node_id"] for e in graph.edges)
    db = tmp_path / "graph.db"
    with open_graph_db(db) as conn:
        save_graph(conn, graph)
        save_graph(conn, graph)
    with open_graph_db(db) as conn:
        loaded = load_graph(conn, tenant_id="one", scan_id="supabase-test")
        assert len(loaded.nodes) == len(graph.nodes)
        assert len(loaded.edges) == len(graph.edges)
        assert not load_graph(conn, tenant_id="two", scan_id="supabase-test").nodes


def test_response_body_is_bounded(monkeypatch):
    import agent_bom.cloud.supabase_inventory as module

    monkeypatch.setattr(module, "MAX_RESPONSE_BYTES", 32)
    report, _ = collect()
    assert report["status"] == "partial"
    assert report["coverage"][0]["state"] == "response_limit"


def test_no_redirect_or_error_body_leaks():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(302, headers={"Location": "https://other.example/secrets"}, text="never-store-this")

    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        report = collect_report(project_refs=[REF], token="test-token", client=client)
    assert len(calls) == 1
    assert "never-store-this" not in json.dumps(report)
    assert report["status"] == "partial"


def test_cli_persists_complete_graph_but_partial_run_preserves_previous(tmp_path, monkeypatch):
    from click.testing import CliRunner

    import agent_bom.cloud.supabase_inventory as module
    from agent_bom.cli._cloud_group import cloud_group
    from agent_bom.db.graph_store import load_graph, open_graph_db

    report, _ = collect()
    token = tmp_path / "token.json"
    token.write_text(json.dumps({"token": "test-token"}))
    token.chmod(0o600)
    output = tmp_path / "report.json"
    db = tmp_path / "graph.db"
    monkeypatch.setattr(module, "collect_report", lambda **kwargs: report)
    args = ["supabase", "--project-ref", REF, "--token-file", str(token), "--output", str(output), "--graph-db", str(db), "--tenant", "one"]
    result = CliRunner().invoke(cloud_group, args)
    assert result.exit_code == 0, result.output
    written = json.loads(output.read_text())
    assert written["persistence"]["graph"] == "persisted"
    with open_graph_db(db) as conn:
        before = load_graph(conn, tenant_id="one")
    assert db.stat().st_mode & 0o077 == 0
    asset = before.nodes[report["findings"][0]["node_id"]]
    assert all(receipt["persisted"] for receipt in asset.attributes["coverage"])
    partial, _ = collect(advisor_status=403)
    monkeypatch.setattr(module, "collect_report", lambda **kwargs: partial)
    result = CliRunner().invoke(cloud_group, args)
    assert result.exit_code == 2
    assert json.loads(output.read_text())["persistence"]["graph"] == "skipped_incomplete"
    with open_graph_db(db) as conn:
        after = load_graph(conn, tenant_id="one")
    assert after.scan_id == before.scan_id
    assert set(after.nodes) == set(before.nodes)


def test_provider_normalizer_retains_native_scope_and_configuration():
    from agent_bom.cloud.resource_model import normalize_cloud_inventory

    report, _ = collect()
    resources = normalize_cloud_inventory(report["cloud_inventory"][0])
    assert len(resources) == 1
    assert resources[0].provider == "supabase"
    assert resources[0].native_type == "supabase.project"
    assert resources[0].account == "org-one"
    assert resources[0].resource_group == REF
    assert resources[0].raw["database_version"] == "17.6"


def test_normalizer_drops_unexpected_fields_from_imported_inventory():
    from agent_bom.cloud.resource_model import normalize_cloud_inventory
    from agent_bom.graph.builder import build_unified_graph_from_report

    report, _ = collect()
    inventory = report["cloud_inventory"][0]
    inventory["projects"][0]["database_password"] = "synthetic-do-not-retain"
    inventory["projects"][0]["api_key"] = "synthetic-do-not-retain"
    normalized = normalize_cloud_inventory(inventory)[0]
    assert "database_password" not in normalized.raw
    assert "api_key" not in normalized.raw
    graph = build_unified_graph_from_report(report, scan_id="imported", tenant_id="one")
    node = graph.nodes[report["findings"][0]["node_id"]]
    assert "database_password" not in node.attributes["configuration"]


def test_cli_rejects_changed_project_scope_without_replacing_snapshot(tmp_path, monkeypatch):
    from click.testing import CliRunner

    import agent_bom.cloud.supabase_inventory as module
    from agent_bom.cli._cloud_group import cloud_group
    from agent_bom.db.graph_store import load_graph, open_graph_db

    token = tmp_path / "token.json"
    token.write_text(json.dumps({"token": "test-token"}))
    token.chmod(0o600)
    db = tmp_path / "graph.db"
    output = tmp_path / "report.json"
    args = ["supabase", "--project-ref", REF, "--token-file", str(token), "--output", str(output), "--graph-db", str(db)]
    report, _ = collect(refs=(REF, OTHER))
    monkeypatch.setattr(module, "collect_report", lambda **kwargs: report)
    assert CliRunner().invoke(cloud_group, args + ["--project-ref", OTHER]).exit_code == 0
    replay, _ = collect(refs=(REF, OTHER))
    monkeypatch.setattr(module, "collect_report", lambda **kwargs: replay)
    repeated = CliRunner().invoke(cloud_group, args + ["--project-ref", OTHER])
    assert repeated.exit_code == 0, repeated.output
    with open_graph_db(db) as conn:
        before = load_graph(conn)
    narrower, _ = collect()
    monkeypatch.setattr(module, "collect_report", lambda **kwargs: narrower)
    result = CliRunner().invoke(cloud_group, args)
    assert result.exit_code == 1
    assert "Collection scope changed; use a separate graph database" in result.output
    rejected = json.loads(output.read_text())
    assert rejected["persistence"]["graph"] == "failed"
    assert all(not receipt["persisted"] for receipt in rejected["coverage"])
    with open_graph_db(db) as conn:
        assert load_graph(conn).scan_id == before.scan_id


def test_redaction_collision_does_not_merge_distinct_advisors():
    keys = ("token=first-private-token", "token=second-private-token")
    report, _ = collect(advisors={"lints": [{**lint(), "cache_key": key} for key in keys]})
    assert report["status"] == "ok"
    assert len({finding["id"] for finding in report["findings"]}) == 2
    assert all(key not in json.dumps(report) for key in keys)
    replay, _ = collect(advisors={"lints": [{**lint(), "cache_key": key} for key in keys]})
    assert [f["id"] for f in report["findings"]] == [f["id"] for f in replay["findings"]]


def test_inactive_project_does_not_emit_unevaluated_advisors():
    report, _ = collect(payload=project(status="INACTIVE"))
    assert report["findings"] == []
    assert report["cloud_inventory"][0]["findings"] == []
    assert report["coverage"][1]["evaluated"] is False
    assert report["coverage"][1]["state"] == "paused"
