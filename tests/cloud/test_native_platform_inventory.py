"""Native account metadata must stay scoped, bounded and explicit about gaps."""

from types import SimpleNamespace

import pytest

from agent_bom.cloud.native_inventory import collect_modal, collect_ngc


def test_modal_uses_verified_workspace_and_native_ids_without_secret_values() -> None:
    reads = []

    def read(args):
        reads.append(args)
        if args[:2] == ["app", "list"]:
            return [{"app_id": "ap-one", "description": "app", "state": "deployed", "tasks": "0", "secret": "do-not-export"}]
        if args[:2] == ["app", "info"]:
            return {"app_id": "ap-one", "functions": {"marker": {"id": "fu-one"}}}
        if args[:2] == ["function", "info"]:
            return {"object_id": "fu-one", "app_id": "ap-one", "name": "marker", "block_network": True, "secrets": ["do-not-export"]}
        if args[:3] == ["environment", "roles", "list"]:
            return {"users": {"alice": "viewer"}, "service_users": {}}
        return []

    ws = SimpleNamespace(name="team-a", hydrate=lambda: None)
    report = collect_modal(workspace="team-a", environment="main", workspace_client=ws, read=read)
    inv = report["cloud_inventory"][0]
    assert {r["native_id"] for r in inv["resources"]} == {"ap-one", "fu-one"}
    assert len({r["id"] for r in inv["resources"]}) == 2
    assert inv["grants"][0]["basis"] == "configured_role"
    assert inv["grants"][0]["role"] == "viewer"
    assert "do-not-export" not in str(report)
    assert not report["reconcile_absent"]
    assert all(args[0] in {"app", "function", "environment", "workspace"} for args in reads)


def test_modal_scope_mismatch_does_not_enumerate() -> None:
    ws = SimpleNamespace(name="another-team", hydrate=lambda: None)
    with pytest.raises(ValueError, match="scope"):
        collect_modal(workspace="team-a", environment="main", workspace_client=ws, read=lambda _: pytest.fail("must not read"))


def test_modal_failed_identity_read_is_incomplete_not_empty_success() -> None:
    def denied(_):
        raise PermissionError("secret value must never reach report")

    ws = SimpleNamespace(name="team-a", hydrate=lambda: None)
    report = collect_modal(workspace="team-a", environment="main", workspace_client=ws, read=denied)
    assert report["status"] == "partial"
    assert all(not r["complete"] for r in report["coverage"])
    assert "secret value" not in str(report)


def ngc_client(*, org="org-a", images=(), users=()):
    return SimpleNamespace(
        users=SimpleNamespace(who=lambda **_: {"orgName": org, "userId": "u1", "type": "PERSONAL_KEY"}, list=lambda **_: iter(users)),
        organization=SimpleNamespace(
            organization=SimpleNamespace(info=lambda **_: {"name": org, "displayName": "Example", "secret": "do-not-export"}),
            team=SimpleNamespace(list=lambda **_: []),
        ),
        registry=SimpleNamespace(image=SimpleNamespace(list=lambda **_: iter(images)), model=SimpleNamespace(list=lambda **_: [])),
    )


def test_ngc_empty_owned_catalog_is_not_public_catalog_or_clean_posture() -> None:
    report = collect_ngc(organization="org-a", client=ngc_client())
    assert report["cloud_inventory"][0]["resources"] == []
    assert not report["clean_posture_assertion"]
    assert not report["reconcile_absent"]
    assert "do-not-export" not in str(report)


def test_ngc_rejects_wrong_organization_before_catalog_reads() -> None:
    with pytest.raises(ValueError, match="scope"):
        collect_ngc(organization="org-a", client=ngc_client(org="other"))


def test_ngc_iterator_denial_preserves_partial_receipt() -> None:
    def denied(**_):
        yield {"id": "u1", "name": "reader"}
        raise PermissionError("private provider details")

    client = ngc_client()
    client.users.list = denied
    report = collect_ngc(organization="org-a", client=client)
    assert report["status"] == "partial"
    assert any(r["capability"] == "users" and not r["complete"] for r in report["coverage"])
    assert "private provider details" not in str(report)


def test_ngc_does_not_adopt_public_catalog_results_as_owned_assets() -> None:
    client = ngc_client(images=[{"name": "pytorch", "namespace": "nvidia", "isPublic": True}])
    report = collect_ngc(organization="org-a", client=client)
    assert report["cloud_inventory"][0]["resources"] == []
    assert report["status"] == "partial"


def test_ngc_row_limit_discloses_truncation() -> None:
    client = ngc_client(images=[{"name": str(i), "namespace": "org-a"} for i in range(3)])
    report = collect_ngc(organization="org-a", client=client, limit=2)
    assert len(report["cloud_inventory"][0]["resources"]) == 2
    assert any(r["state"] == "truncated" for r in report["coverage"])


def test_ngc_rejects_model_from_another_team() -> None:
    client = ngc_client()
    client.registry.model.list = lambda **_: [{"name": "model", "orgName": "org-a", "teamName": "other-team"}]
    report = collect_ngc(organization="org-a", client=client)
    assert report["cloud_inventory"][0]["resources"] == []
    assert report["status"] == "partial"


def test_ngc_malformed_team_is_partial_instead_of_discarding_other_evidence() -> None:
    client = ngc_client()
    client.organization.team.list = lambda **_: [{"name": "invalid/team"}]
    report = collect_ngc(organization="org-a", client=client)
    assert report["cloud_inventory"][0]["organizations"]
    assert report["status"] == "partial"


def test_ngc_conflicting_resource_ids_do_not_duplicate_assets() -> None:
    client = ngc_client(images=[{"name": "image", "namespace": "org-a", "latestTag": tag} for tag in ("old", "new")])
    report = collect_ngc(organization="org-a", client=client)
    assert len(report["cloud_inventory"][0]["resources"]) == 1
    assert report["status"] == "partial"


def test_ngc_invalid_identity_is_not_complete_empty_metadata() -> None:
    report = collect_ngc(organization="org-a", client=ngc_client(users=[{"unexpected": "schema"}]))
    assert report["cloud_inventory"][0]["users"] == []
    assert any(r["capability"] == "users" and not r["complete"] for r in report["coverage"])


def test_ngc_caller_roles_remain_scoped_configuration_not_effective_access() -> None:
    client = ngc_client()
    client.users.who = lambda **_: {
        "orgName": "org-a",
        "userId": "u1",
        "user": {
            "roles": [
                {"org": {"name": "other"}, "orgRoles": ["ORG_OWNER"]},
                {"org": {"name": "org-a"}, "orgRoles": ["ORG_MEMBER"]},
            ]
        },
    }
    report = collect_ngc(organization="org-a", client=client)
    grants = report["cloud_inventory"][0]["grants"]
    assert grants == [{"principal": "u1", "role": "ORG_MEMBER", "organization": "org-a", "basis": "configured_caller_role"}]
    assert not any(receipt["evaluated"] for receipt in report["coverage"])
