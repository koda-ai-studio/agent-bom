"""Directory evidence is scoped, durable, and never effective-access proof."""

import copy
import json

import httpx
import pytest

from agent_bom.cloud.platform_directory import collect_supabase_directory, collect_vercel_directory
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.correlation import CorrelationSnapshot, merge_graph_snapshots
from agent_bom.graph.types import EntityType, RelationshipType


def directory(provider, account, *, confirmed=True, denied=False):
    def handler(request):
        if request.url.path.endswith("/members"):
            if denied:
                return httpx.Response(403, json={})
            if provider == "supabase":
                return httpx.Response(200, json=[{"user_id": "u1", "user_name": "Reader", "role_name": "Read-only"}])
            return httpx.Response(
                200,
                json={
                    "members": [{"uid": "u1", "username": "Reader", "role": "MEMBER", "confirmed": confirmed}],
                    "pagination": {"next": None},
                },
            )
        if request.url.path.endswith("/projects"):
            return httpx.Response(200, json={"projects": [], "pagination": {"count": 0, "offset": 0, "limit": 100}})
        return httpx.Response(200, json={"id": account, "name": "Example directory"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        if provider == "supabase":
            return collect_supabase_directory(organization=account, token="fixture", client=client)
        return collect_vercel_directory(team=account, token="fixture", client=client)


def graph(report, scan="one", tenant="tenant-a"):
    inventory = {
        "provider": report["provider"],
        "account_id": report["account_id"],
        "directory": report,
        "projects": [],
        "deployments": [],
        "findings": [],
        "coverage": report["coverage"],
    }
    return build_unified_graph_from_report(json.loads(json.dumps({"cloud_inventory": [inventory]})), scan_id=scan, tenant_id=tenant)


@pytest.mark.parametrize("provider,account", [("supabase", "a" * 20), ("vercel", "team_a")])
def test_membership_and_role_are_persisted_without_access_inference(tmp_path, provider, account):
    from agent_bom.db.graph_store import load_graph, open_graph_db, save_graph

    source = directory(provider, account)
    first = graph(source)
    assert len(first.nodes_by_type(EntityType.USER)) == 1
    assert len(first.nodes_by_type(EntityType.ROLE)) == 1
    memberships = [e for e in first.edges if e.relationship == RelationshipType.MEMBER_OF]
    assert len(memberships) == 2
    assert all(e.traversable is False and e.evidence["effective_access"] == "not_evaluated" for e in memberships)
    assert not any(
        e.relationship in {RelationshipType.CAN_ACCESS, RelationshipType.HAS_PERMISSION, RelationshipType.ACCESSED} for e in first.edges
    )
    with open_graph_db(tmp_path / "graph.db") as conn:
        save_graph(conn, first)
    with open_graph_db(tmp_path / "graph.db") as conn:
        restored = load_graph(conn, tenant_id="tenant-a", scan_id="one")
        assert not load_graph(conn, tenant_id="tenant-b", scan_id="one").nodes
    assert set(restored.nodes) == set(first.nodes)
    assert all(e.traversable is False for e in restored.edges)
    assert restored.nodes_by_type(EntityType.USER)[0].attributes["native_id"] == "u1"


@pytest.mark.parametrize("provider,accounts", [("supabase", ["a" * 20, "b" * 20]), ("vercel", ["team_a", "team_b"])])
def test_native_identity_correlates_only_within_its_directory(provider, accounts):
    snapshots = []
    for number, account in enumerate([accounts[0], accounts[0], accounts[1]]):
        report = directory(provider, account)
        report["identities"][0]["name"] = f"Renamed {number}"
        snapshots.append(CorrelationSnapshot.from_graph(graph(report, str(number))))
    result = merge_graph_snapshots(correlation_id="merged", tenant_id="tenant-a", snapshots=snapshots).graph
    users = result.nodes_by_type(EntityType.USER)
    assert len(users) == 2
    assert sorted(len(u.attributes["correlation"]["source_scan_ids"]) for u in users) == [1, 2]
    assert len(result.nodes_by_type(EntityType.ROLE)) == 2
    assert all(e.traversable is False for e in result.edges)


def test_pending_vercel_membership_does_not_create_a_granted_role():
    report = directory("vercel", "team_a", confirmed=False)
    result = graph(report)
    assert len(result.nodes_by_type(EntityType.USER)) == 1
    assert result.nodes_by_type(EntityType.USER)[0].attributes["confirmed"] is False
    assert not result.edges and not result.nodes_by_type(EntityType.ROLE)


@pytest.mark.parametrize("mutation", ["account", "provider", "native_id"])
def test_unqualified_imported_members_do_not_become_scoped_principals(mutation):
    report = directory("vercel", "team_a")
    member = report["identities"][0]
    member[{"account": "account_id", "provider": "provider", "native_id": "native_id"}[mutation]] = {
        "account": "team_elsewhere",
        "provider": "supabase",
        "native_id": "",
    }[mutation]
    assert not graph(report).nodes_by_type(EntityType.USER)


def test_imported_identity_key_cannot_redirect_membership_to_another_principal():
    report = directory("vercel", "team_a")
    expected = report["identities"][0]["id"]
    report["identities"][0]["id"] = "user:elsewhere"
    result = graph(report)
    assert expected in result.nodes and "user:elsewhere" not in result.nodes
    assert all(e.source == expected for e in result.edges)


def test_conflicting_grant_scope_is_not_projected():
    report = directory("vercel", "team_a")
    report["grants"][0]["account_id"] = "team_b"
    result = graph(report)
    assert len(result.nodes_by_type(EntityType.USER)) == 1
    assert not result.nodes_by_type(EntityType.ROLE)


def test_denied_directory_keeps_explicit_incomplete_coverage():
    report = directory("vercel", "team_a", denied=True)
    result = graph(report)
    account = result.nodes["account:vercel:team_a"]
    assert any(r["state"] == "denied" and not r["complete"] for r in account.attributes["directory_coverage"])
    assert not result.nodes_by_type(EntityType.USER)
    assert account.attributes["service_identities_state"] == "not_collected"
    assert account.attributes["observed_communication_state"] == "not_collected"


def test_directory_scope_cannot_override_inventory_scope():
    report = directory("vercel", "team_a")
    wrong = copy.deepcopy(report)
    wrong["account_id"] = "team_b"
    inventory = {"provider": "vercel", "account_id": "team_a", "directory": wrong, "projects": [], "deployments": []}
    result = build_unified_graph_from_report({"cloud_inventory": [inventory]}, scan_id="one", tenant_id="tenant-a")
    assert not result.nodes_by_type(EntityType.USER)


def test_conflicting_imported_identity_does_not_merge_roles():
    report = directory("vercel", "team_a")
    conflict = {**report["identities"][0], "role": "OWNER"}
    report["identities"].append(conflict)
    result = graph(report)
    assert not result.nodes_by_type(EntityType.USER)
    assert result.nodes["account:vercel:team_a"].attributes["directory_projection_state"] == "incomplete"


def test_redacted_native_ids_are_unresolved_instead_of_collapsing():
    def handler(request):
        if request.url.path.endswith("/members"):
            return httpx.Response(
                200,
                json={
                    "members": [
                        {"uid": "token=first-private-token", "role": "MEMBER", "confirmed": True},
                        {"uid": "token=second-private-token", "role": "MEMBER", "confirmed": True},
                    ],
                    "pagination": {"next": None},
                },
            )
        return httpx.Response(200, json={"id": "team_a", "name": "Example"})

    report = collect_vercel_directory(team="team_a", token="fixture", client=client_for_redaction(handler))
    result = graph(report)
    assert not result.nodes_by_type(EntityType.USER)
    assert result.nodes["account:vercel:team_a"].attributes["directory_projection_state"] == "incomplete"


def client_for_redaction(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_local_snapshot_order_uses_observation_time_not_uuid_or_arrival(tmp_path):
    from datetime import datetime, timezone

    from agent_bom.cli._cloud_inventory_io import persist_graph
    from agent_bom.db.graph_store import load_graph, open_graph_db

    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    directory_report = directory("vercel", "team_a")
    db, output = tmp_path / "graph.db", tmp_path / "report.json"
    for scan_id, observed_at, name in [
        ("z-older", f"{day}T00:00:00.100000Z", "Old"),
        ("a-newer", f"{day}T00:00:00.200000Z", "New"),
        ("zz-late-arrival", f"{day}T00:00:00.050000Z", "Stale"),
    ]:
        directory_report["identities"][0]["name"] = name
        report = {
            "scan_id": scan_id,
            "observed_at": observed_at,
            "coverage": [],
            "cloud_inventory": [
                {
                    "provider": "vercel",
                    "account_id": "team_a",
                    "projects": [],
                    "deployments": [],
                    "directory": directory_report,
                }
            ],
        }
        persist_graph(report, db, "tenant-a", output, scope_entity_types={"account"}, scope_node_ids={"account:vercel:team_a"})
    with open_graph_db(db) as conn:
        current = load_graph(conn, tenant_id="tenant-a")
    assert current.scan_id == "a-newer"
    assert current.nodes_by_type(EntityType.USER)[0].label == "New"


def test_graph_import_does_not_require_optional_http_collector():
    """The graph model must remain importable by the minimal package install."""
    import subprocess
    import sys

    script = """
import builtins
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name in {"httpx", "agent_bom.cloud.platform_directory"}:
        raise ModuleNotFoundError("Native HTTP collector is unavailable in the minimal installation")
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
from agent_bom.graph.builder import build_unified_graph_from_report
assert build_unified_graph_from_report({}, scan_id="minimal", tenant_id="fixture") is not None
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
