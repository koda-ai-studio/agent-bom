"""Scoped platform directories must preserve incompleteness and authority boundaries."""

import httpx
import pytest

from agent_bom.cloud.platform_directory import collect_supabase_directory, collect_vercel_directory

ORG = "a" * 20
REF = "b" * 20


def client_for(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def supabase_handler(request):
    assert request.method == "GET"
    if request.url.path.endswith("/members"):
        return httpx.Response(
            200,
            json=[
                {
                    "user_id": "user-1",
                    "user_name": "reader",
                    "email": "reader@example.test",
                    "role_name": "Read-only",
                    "mfa_enabled": True,
                    "secret": "never",
                }
            ],
        )
    if request.url.path.endswith("/projects"):
        return httpx.Response(200, json={"projects": [{"ref": REF, "name": "db"}], "pagination": {"count": 1, "offset": 0, "limit": 100}})
    return httpx.Response(200, json={"id": ORG, "name": "Example"})


def test_supabase_directory_carries_membership_and_project_scope_only():
    report = collect_supabase_directory(organization=ORG, token="private", client=client_for(supabase_handler))
    assert report["account_id"] == ORG and report["project_refs"] == [REF]
    assert report["identities"][0]["native_id"] == "user-1"
    assert report["grants"][0]["basis"] == "configured_membership"
    assert report["grants"][0]["effective_access"] == "not_evaluated"
    assert all(r["complete"] for r in report["coverage"])
    assert "never" not in str(report) and "private" not in str(report)
    assert report["cross_account_trust"]["state"] == "not_collected"
    assert report["observed_communication"]["state"] == "not_collected"


def test_supabase_wrong_organization_stops_subordinate_reads():
    paths = []

    def handler(request):
        paths.append(request.url.path)
        return httpx.Response(200, json={"id": "other", "name": "wrong"})

    report = collect_supabase_directory(organization=ORG, token="private", client=client_for(handler))
    assert len(paths) == 1 and not report["identities"] and not report["project_refs"]
    assert not all(r["complete"] for r in report["coverage"])


def test_supabase_denied_members_preserve_other_directory_evidence():
    def handler(request):
        if request.url.path.endswith("/members"):
            return httpx.Response(403, json={"message": "secret"})
        return supabase_handler(request)

    report = collect_supabase_directory(organization=ORG, token="private", client=client_for(handler))
    assert report["project_refs"] == [REF] and report["identities"] == []
    assert any(r["state"] == "denied" and not r["complete"] for r in report["coverage"])
    assert "secret" not in str(report)


def test_supabase_offset_pagination_is_exhausted():
    def handler(request):
        if not request.url.path.endswith("/projects"):
            return supabase_handler(request)
        offset = int(request.url.params.get("offset", "0"))
        return httpx.Response(
            200, json={"projects": [{"ref": ("b" if offset == 0 else "c") * 20}], "pagination": {"count": 2, "offset": offset, "limit": 1}}
        )

    report = collect_supabase_directory(organization=ORG, token="private", client=client_for(handler))
    assert report["project_refs"] == ["b" * 20, "c" * 20]
    assert next(r for r in report["coverage"] if r["capability"] == "organization_projects")["complete"]


@pytest.mark.parametrize("pagination", [{}, {"count": 2, "offset": 99, "limit": 100}, {"count": True, "offset": 0, "limit": 100}])
def test_supabase_bad_pagination_cannot_claim_complete(pagination):
    def handler(request):
        if request.url.path.endswith("/projects"):
            return httpx.Response(200, json={"projects": [{"ref": REF}], "pagination": pagination})
        return supabase_handler(request)

    report = collect_supabase_directory(organization=ORG, token="private", client=client_for(handler))
    assert not next(r for r in report["coverage"] if r["capability"] == "organization_projects")["complete"]


def vercel_handler(request):
    if request.url.path.endswith("/members"):
        return httpx.Response(
            200,
            json={
                "members": [{"uid": "u1", "username": "reader", "role": "MEMBER", "confirmed": True, "mfaEnabled": False}],
                "pagination": {},
                "totalCount": 1,
            },
        )
    return httpx.Response(200, json={"id": "team_a", "name": "A"})


def test_vercel_exact_total_proves_terminal_members_page():
    result = collect_vercel_directory(team="team_a", token="private", client=client_for(vercel_handler))
    assert result["identities"][0]["native_id"] == "u1"
    assert result["grants"][0]["role"] == "MEMBER"
    assert all(r["complete"] for r in result["coverage"])


def test_vercel_missing_continuation_without_total_is_partial():
    def handler(request):
        if request.url.path.endswith("/members"):
            return httpx.Response(200, json={"members": [], "pagination": {}})
        return vercel_handler(request)

    result = collect_vercel_directory(team="team_a", token="private", client=client_for(handler))
    assert not result["coverage"][-1]["complete"]


def test_same_user_id_in_two_accounts_has_distinct_identity():
    def get(team):
        def handler(request):
            if not request.url.path.endswith("/members"):
                return httpx.Response(200, json={"id": team, "name": team})
            return vercel_handler(request)

        return collect_vercel_directory(team=team, token="private", client=client_for(handler))["identities"][0]["id"]

    assert get("team_a") != get("team_b")


def test_redaction_does_not_collapse_distinct_native_members_or_grants():
    native_ids = ["token=first-private-token", "token=second-private-token"]

    def handler(request):
        if request.url.path.endswith("/members"):
            return httpx.Response(
                200, json={"members": [{"uid": uid, "role": "MEMBER"} for uid in native_ids], "pagination": {}, "totalCount": 2}
            )
        return vercel_handler(request)

    report = collect_vercel_directory(team="team_a", token="private", client=client_for(handler))
    assert len({r["id"] for r in report["identities"]}) == 2
    assert len({r["id"] for r in report["grants"]}) == 2
    assert all(uid not in str(report) for uid in native_ids)


def test_duplicate_conflicting_member_is_partial():
    def handler(request):
        if request.url.path.endswith("/members"):
            return httpx.Response(
                200, json={"members": [{"uid": "u1", "role": "OWNER"}, {"uid": "u1", "role": "MEMBER"}], "pagination": {}, "totalCount": 2}
            )
        return vercel_handler(request)

    report = collect_vercel_directory(team="team_a", token="private", client=client_for(handler))
    assert not report["coverage"][-1]["complete"]
    assert not report["grants"]


def test_organization_push_keeps_directory_and_project_scopes_separate():
    from agent_bom.cloud.connector_push import connector_push_payloads
    from agent_bom.cloud.supabase_inventory import collect_report

    def handler(request):
        if "/organizations/" in request.url.path:
            return supabase_handler(request)
        if request.url.path.endswith("/advisors/security"):
            return httpx.Response(200, json={"lints": []})
        return httpx.Response(200, json={"ref": REF, "name": "db", "region": "region", "status": "ACTIVE_HEALTHY", "organization_id": ORG})

    report = collect_report(project_refs=[], organization=ORG, token="private", client=client_for(handler))
    payloads = connector_push_payloads(report)
    assert len(payloads) == 2 and len({p["target_scope"] for p in payloads}) == 2
    directory = next(p for p in payloads if "directory" in p["cloud_inventory"][0])
    project = next(p for p in payloads if "directory" not in p["cloud_inventory"][0])
    assert directory["cloud_inventory"][0]["directory"]["identities"]
    assert all("project_ref" not in r for r in directory["coverage"])
    assert all(r["project_ref"] == REF for r in project["coverage"])


def test_organization_rejects_project_returned_from_other_account():
    from agent_bom.cloud.supabase_inventory import collect_report

    def handler(request):
        if "/organizations/" in request.url.path:
            return supabase_handler(request)
        return httpx.Response(
            200, json={"ref": REF, "name": "db", "region": "region", "status": "ACTIVE_HEALTHY", "organization_id": "other"}
        )

    report = collect_report(project_refs=[], organization=ORG, token="private", client=client_for(handler))
    assert report["status"] == "partial"
    assert all(not i["projects"] for i in report["cloud_inventory"])


@pytest.mark.parametrize("pagination,total", [({"next": None, "hasNext": True}, 1), ({"next": None}, True), ({"next": None}, -1)])
def test_vercel_contradictory_pagination_is_incomplete(pagination, total):
    def handler(request):
        if request.url.path.endswith("/members"):
            return httpx.Response(200, json={"members": [{"uid": "u1", "role": "MEMBER"}], "pagination": pagination, "totalCount": total})
        return vercel_handler(request)

    report = collect_vercel_directory(team="team_a", token="private", client=client_for(handler))
    assert not report["coverage"][-1]["complete"]


def test_directory_receipts_declare_supported_projection_without_claiming_persistence():
    report = collect_supabase_directory(organization=ORG, token="private", client=client_for(supabase_handler))
    assert all(r["graph_supported"] is True and r["persisted"] is False for r in report["coverage"])


def test_cli_persists_project_and_directory_membership(tmp_path, monkeypatch):
    import json

    from click.testing import CliRunner

    import agent_bom.cloud.supabase_inventory as module
    from agent_bom.cli._cloud_group import cloud_group

    def handler(request):
        if "/organizations/" in request.url.path:
            return supabase_handler(request)
        if request.url.path.endswith("/advisors/security"):
            return httpx.Response(200, json={"lints": []})
        return httpx.Response(200, json={"ref": REF, "name": "db", "region": "region", "status": "ACTIVE_HEALTHY", "organization_id": ORG})

    report = module.collect_report(project_refs=[], organization=ORG, token="private", client=client_for(handler))
    monkeypatch.setattr(module, "collect_report", lambda **kwargs: report)
    token, output, db = (tmp_path / name for name in ("token.json", "report.json", "graph.db"))
    token.write_text(json.dumps({"token": "private"}))
    token.chmod(0o600)
    result = CliRunner().invoke(
        cloud_group, ["supabase", "--organization-slug", ORG, "--token-file", str(token), "--output", str(output), "--graph-db", str(db)]
    )
    assert result.exit_code == 0, result.output
    written = json.loads(output.read_text())
    assert written["persistence"]["graph"] == "persisted"
    directory = [r for r in written["coverage"] if r.get("graph_supported") is True]
    assert directory and all(r["persisted"] for r in directory)
    from agent_bom.db.graph_store import load_graph, open_graph_db
    from agent_bom.graph.types import EntityType

    with open_graph_db(db) as conn:
        restored = load_graph(conn, tenant_id=written["persistence"]["tenant_id"])
    assert len(restored.nodes_by_type(EntityType.USER)) == 1


def test_org_cli_reconciles_project_changes_without_changing_directory(tmp_path, monkeypatch):
    import json

    from click.testing import CliRunner

    import agent_bom.cloud.supabase_inventory as module
    from agent_bom.cli._cloud_group import cloud_group
    from agent_bom.db.graph_store import load_graph, open_graph_db
    from agent_bom.graph.types import EntityType

    state = {"refs": [REF], "denied": False}

    def handler(request):
        if request.url.path.endswith("/projects") and "/organizations/" in request.url.path:
            refs = state["refs"]
            return httpx.Response(
                200, json={"projects": [{"ref": r} for r in refs], "pagination": {"count": len(refs), "offset": 0, "limit": 100}}
            )
        if "/organizations/" in request.url.path:
            if request.url.path.endswith("/members") and state["denied"]:
                return httpx.Response(403, json={})
            return supabase_handler(request)
        if request.url.path.endswith("/advisors/security"):
            return httpx.Response(200, json={"lints": []})
        ref = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json={"ref": ref, "name": "db", "region": "region", "status": "ACTIVE_HEALTHY", "organization_id": ORG})

    collector = module.collect_report
    monkeypatch.setattr(module, "collect_report", lambda **kwargs: collector(**kwargs, client=client_for(handler)))
    token, output, db = (tmp_path / name for name in ("token.json", "report.json", "graph.db"))
    token.write_text(json.dumps({"token": "private"}))
    token.chmod(0o600)
    args = [
        "supabase",
        "--organization-slug",
        ORG,
        "--token-file",
        str(token),
        "--output",
        str(output),
        "--graph-db",
        str(db),
        "--tenant",
        "fixture",
    ]
    for refs, denied, expected in [
        ([REF], False, 1),
        ([], True, 1),
        ([], False, 0),
        ([REF], False, 1),
        ([REF, "c" * 20], False, 2),
        ([REF, "c" * 20], False, 2),
    ]:
        state.update(refs=refs, denied=denied)
        result = CliRunner().invoke(cloud_group, args)
        assert result.exit_code == (2 if denied else 0), result.output
        with open_graph_db(db) as conn:
            restored = load_graph(conn, tenant_id="fixture")
        assert len(restored.nodes_by_type(EntityType.CLOUD_RESOURCE)) == expected
        assert len(restored.nodes_by_type(EntityType.USER)) == 1
