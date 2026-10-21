"""Human directory identities must survive native inventory and graph projection."""

from agent_bom.cloud import azure_inventory
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType
from agent_bom.identity.entra_nhi import EntraClient


class Directory:
    def list_service_principals(self):
        return []

    def list_groups(self):
        return []

    def list_users(self):
        return [
            {"id": "user-1", "displayName": "Demo User", "accountEnabled": False, "password": "must-not-copy"},
            {"displayName": "no-id"},
        ]


def inventory(monkeypatch, client):
    monkeypatch.setattr(azure_inventory, "_resolve_session", lambda empty, credential, sub, warnings: (object(), sub, None))
    monkeypatch.setattr(azure_inventory, "_inventory_discovery_tasks", lambda **kwargs: [])
    monkeypatch.setattr(azure_inventory, "_discover_management_groups", lambda credential: ([], []))
    monkeypatch.setattr(azure_inventory, "_entra_directory_client", lambda *args, **kwargs: client)
    return azure_inventory.discover_inventory(subscription_id="sub-1", force=True)


def test_users_flow_from_native_inventory_to_scoped_graph(monkeypatch):
    payload = inventory(monkeypatch, Directory())
    assert len(payload["entra_users"]) == 1
    assert payload["entra_users"][0]["account_enabled"] is False
    assert "must-not-copy" not in str(payload)
    graph = build_unified_graph_from_report({"agents": [], "cloud_inventory": payload}, tenant_id="tenant-a")
    user = graph.nodes["user:azure:user-1"]
    assert user.entity_type == EntityType.USER
    assert user.label == "Demo User"
    assert user.attributes["principal_resource_id"] == "user-1"


def test_denied_user_read_keeps_other_inventory_and_records_missing_permission(monkeypatch):
    class Denied(Directory):
        def list_users(self):
            raise RuntimeError("403 Forbidden")

    payload = inventory(monkeypatch, Denied())
    assert payload["entra_users"] == []
    assert payload["warnings"]
    assert payload["missing_permissions"]


def test_disabled_directory_does_not_claim_user_enumeration(monkeypatch):
    payload = inventory(monkeypatch, None)
    assert payload["entra_users"] == []
    assert "Directory.Read.All" not in payload["discovery_envelope"]["permissions_used"]


def test_user_listing_uses_metadata_only_graph_query(monkeypatch):
    paths = []
    monkeypatch.setattr(EntraClient, "_get", lambda self, path: paths.append(path) or [])
    assert EntraClient("fake-token").list_users() == []
    assert paths == ["/users?$top=999&$select=id,displayName,accountEnabled,userType"]
