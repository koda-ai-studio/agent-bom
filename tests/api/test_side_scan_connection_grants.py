"""Operator lifecycle grants bind snapshot execution to exact tenant resources."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from agent_bom.api import side_scan_authorization as auth
from agent_bom.api.connection_store import CloudConnectionRecord
from agent_bom.cloud.side_scan import SideScanConfigError


@pytest.fixture
def scope(tmp_path, monkeypatch):
    record = CloudConnectionRecord(
        id="connection-a",
        tenant_id="tenant-a",
        provider="azure",
        display_name="Scanner",
        role_ref="lifecycle-client",
        external_id_encrypted="",
        auth_params={
            "auth_mode": "managed_identity",
            "credential_binding": "binding-a",
            "tenant_id": "directory-a",
            "subscription_id": "subscription-a",
        },
    )
    request = dict(
        tenant_id="tenant-a",
        connection_id=record.id,
        provider="azure",
        account_id="subscription-a",
        target_id="/subscriptions/subscription-a/resourceGroups/disks/providers/Microsoft.Compute/disks/os",
        collector_id="collector-a",
        location="eastus",
        collector_resource_group="collectors",
    )
    binding = dict(
        tenant_id="tenant-a",
        provider="azure",
        auth_mode="managed_identity",
        role_ref=record.role_ref,
        scope_id="subscription-a",
        directory_tenant_id="directory-a",
        expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        side_scan={
            "targets": [request["target_id"]],
            "collectors": ["collector-a"],
            "locations": ["eastus"],
            "collector_resource_groups": ["collectors"],
        },
    )
    path = tmp_path / "bindings.json"

    def save():
        path.write_text(json.dumps({"bindings": {"binding-a": binding}}))

    save()
    monkeypatch.setenv("AGENT_BOM_CONNECTION_WORKLOAD_BINDINGS_FILE", str(path))
    monkeypatch.setattr(
        auth,
        "get_connection_store",
        lambda: SimpleNamespace(get=lambda tenant, connection: record if (tenant, connection) == (record.tenant_id, record.id) else None),
    )
    return request, binding, record, save


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "tenant-b"),
        ("connection_id", "foreign"),
        ("provider", "gcp"),
        ("account_id", "subscription-b"),
        ("target_id", "/subscriptions/subscription-b/resourceGroups/disks/providers/Microsoft.Compute/disks/os"),
        ("collector_id", "other-collector"),
        ("location", "westus"),
        ("collector_resource_group", "other-group"),
    ],
)
def test_cross_boundary_requests_cannot_construct_credentials(scope, monkeypatch, field, value):
    request, _, _, _ = scope
    calls = []
    monkeypatch.setattr(auth, "broker_side_scan_binding", lambda *a: calls.append(a))
    with pytest.raises(SideScanConfigError):
        auth.authorize_side_scan(**{**request, field: value})
    assert calls == []


@pytest.mark.parametrize("change", ["disabled", "expired", "no_grant", "demo", "scope", "role"])
def test_unusable_binding_never_constructs_credentials(scope, monkeypatch, change):
    request, binding, record, save = scope
    if change == "disabled":
        binding["enabled"] = False
    elif change == "expired":
        binding["expires_at"] = "2020-01-01T00:00:00+00:00"
    elif change == "no_grant":
        binding.pop("side_scan")
    elif change == "demo":
        record.auth_params["demo"] = True
    elif change == "scope":
        binding["scope_id"] = "other"
    else:
        binding["role_ref"] = "other"
    save()
    calls = []
    monkeypatch.setattr(auth, "broker_side_scan_binding", lambda *a: calls.append(a))
    with pytest.raises(SideScanConfigError):
        auth.authorize_side_scan(**request)
    assert calls == []


def test_bound_clients_get_only_the_authorized_credential_and_recheck_policy(scope, monkeypatch):
    request, binding, _, save = scope
    credential = object()
    calls = []
    monkeypatch.setattr(auth, "broker_side_scan_binding", lambda b: credential)
    monkeypatch.setattr(auth, "_default_provider_clients", lambda provider, **kw: calls.append((provider, kw)) or {"bound": credential})
    authorization = auth.authorize_side_scan(**request)
    assert calls == []
    assert authorization["authorization_ref"].startswith("connection-a:")
    factory = authorization["client_factory"]
    assert factory("azure", account_id="subscription-a", region=None) == {"bound": credential}
    assert calls == [("azure", {"account_id": "subscription-a", "region": None, "credential": credential})]
    binding["side_scan"]["targets"] = ["another-disk"]
    save()
    with pytest.raises(SideScanConfigError):
        factory("azure", account_id="subscription-a", region=None)
    assert len(calls) == 1


@pytest.mark.parametrize("surface", ["mcp", "scheduler"])
def test_server_surfaces_refuse_unowned_connections_before_executor(scope, monkeypatch, surface):
    import asyncio

    from agent_bom.api.side_scan_scheduler import ScheduledSideScanTarget, run_scheduled_side_scan_once
    from agent_bom.cloud import side_scan_targets
    from agent_bom.mcp_tools.side_scan import cloud_side_scan_impl

    request, _, _, _ = scope
    request = {**request, "connection_id": "foreign"}
    calls = []

    async def execute(**kwargs):
        calls.append(kwargs)
        return []

    monkeypatch.setattr(side_scan_targets, "run_provider_side_scan", execute)
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-a")
    if surface == "mcp":
        result = json.loads(asyncio.run(cloud_side_scan_impl(**request, _truncate_response=lambda s: s)))
    else:
        result = run_scheduled_side_scan_once(ScheduledSideScanTarget(**request))
    assert result["status"] == "unavailable"
    assert calls == []


@pytest.mark.parametrize("prefix", ["", "https://www.googleapis.com/compute/v1/", "https://compute.googleapis.com/compute/v1/"])
def test_gcp_grant_accepts_canonical_provider_resource_urls(scope, prefix):
    request, binding, record, save = scope
    record.provider = "gcp"
    record.role_ref = "scanner@project.iam.gserviceaccount.com"
    record.auth_params = {"auth_mode": "workload_identity", "credential_binding": "binding-a", "project_id": "project-a"}
    target = prefix + "projects/project-a/zones/zone-a/disks/os"
    binding.update(
        provider="gcp",
        auth_mode="workload_identity",
        role_ref=record.role_ref,
        scope_id="project-a",
        directory_tenant_id="",
        token_file_path="/var/run/projected-token",
        audience="//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
        side_scan={"targets": [target], "collectors": ["collector-a"], "locations": ["zone-a"]},
    )
    save()
    result = auth.authorize_side_scan(
        **{
            **request,
            "provider": "gcp",
            "account_id": "project-a",
            "target_id": target,
            "location": "zone-a",
            "collector_resource_group": None,
        }
    )
    assert result["authorization_ref"].startswith("connection-a:")
