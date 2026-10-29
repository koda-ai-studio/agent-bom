"""Connection inventory, posture and sensitive-data evidence share scope."""

from unittest.mock import MagicMock

import pytest

from agent_bom.api import connection_scan_providers as scans
from agent_bom.api.connection_store import CloudConnectionRecord


def _record(provider):
    key = "subscription_id" if provider == "azure" else "project_id"
    return CloudConnectionRecord(
        id="connection-scope",
        tenant_id="tenant-a",
        provider=provider,
        display_name="Scoped connection",
        role_ref="readonly",
        external_id_encrypted="",
        regions=[],
        status="active",
        created_at="2026-10-01T00:00:00Z",
        updated_at="2026-10-01T00:00:00Z",
        inventory_scope="organization",
        auth_params={key: "anchor"},
    )


@pytest.mark.parametrize("provider", ["azure", "gcp"])
def test_org_cis_uses_each_inventory_scope_and_the_brokered_credential(monkeypatch, provider):
    from agent_bom.cloud import azure_cis_benchmark, azure_inventory, gcp_cis_benchmark, gcp_inventory

    azure = provider == "azure"
    key = "subscription_id" if azure else "project_id"
    credential_key = "credential" if azure else "credentials"
    inventories = [
        {"provider": provider, "status": "ok", key: scope, "account_id": scope, "warnings": ["scope incomplete"]}
        for scope in ["scope-b", "scope-a"]
    ]
    inventory_module = azure_inventory if azure else gcp_inventory
    inventory_function = "discover_all_subscription_inventories" if azure else "discover_all_project_inventories"
    monkeypatch.setattr(inventory_module, inventory_function, lambda **kwargs: inventories)
    credential = object()
    monkeypatch.setattr("agent_bom.cloud.connection_broker.broker_session", lambda *a, **k: credential)
    report_class = azure_cis_benchmark.AzureCISReport if azure else gcp_cis_benchmark.GCPCISReport
    run = MagicMock(side_effect=lambda **kwargs: report_class(**{key: kwargs[key]}))
    monkeypatch.setattr(azure_cis_benchmark if azure else gcp_cis_benchmark, "run_benchmark", run)
    retained = []
    monkeypatch.setattr(scans, "_persist_connection_report", lambda record, tenant, report, **kw: retained.append(report) or "scan-scopes")

    result = getattr(scans, f"_run_{provider}_connection_scan")(_record(provider), "tenant-a")

    assert sorted(call.kwargs[key] for call in run.call_args_list) == ["scope-a", "scope-b"]
    assert all(call.kwargs[credential_key] is credential for call in run.call_args_list)
    data = getattr(retained[0], f"{provider}_cis_benchmark_data")
    assert data["subscriptions_scanned" if azure else "projects_scanned"] == ["scope-a", "scope-b"]
    assert result["cis_benchmark"]["accounts_scanned"] == 2
    assert result["inventory"]["status"] == "partial"


def test_azure_org_dspm_retains_each_subscription_attribution(monkeypatch):
    from agent_bom.cloud import azure_cis_benchmark, azure_inventory, dspm_findings

    inventories = [{"provider": "azure", "status": "ok", "subscription_id": scope} for scope in ["scope-a", "scope-b"]]
    monkeypatch.setattr(azure_inventory, "discover_all_subscription_inventories", lambda **kw: inventories)
    monkeypatch.setattr("agent_bom.cloud.connection_broker.broker_session", lambda *a, **k: object())
    monkeypatch.setattr(
        azure_cis_benchmark, "run_benchmark", lambda **kw: azure_cis_benchmark.AzureCISReport(subscription_id=kw["subscription_id"])
    )
    build = MagicMock(return_value=[])
    monkeypatch.setattr(dspm_findings, "build_inventory_dspm_findings", build)
    monkeypatch.setattr(scans, "_persist_connection_report", lambda *a, **kw: "scan-scopes")

    scans._run_azure_connection_scan(_record("azure"), "tenant-a")

    assert [call.args[0] for call in build.call_args_list] == inventories
    assert [call.kwargs["account_ref"] for call in build.call_args_list] == ["azure:scope-a", "azure:scope-b"]


@pytest.mark.parametrize("provider", ["azure", "gcp"])
def test_explicit_empty_scope_never_falls_back_to_ambient(monkeypatch, provider):
    from agent_bom.cloud import azure_cis_benchmark, azure_inventory, gcp_cis_benchmark, gcp_organizations
    from agent_bom.cloud.base import CloudDiscoveryError

    def unexpected(*args, **kwargs):
        pytest.fail("Explicit scope must not enumerate or use an ambient project")

    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "ambient-subscription")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "ambient-project")
    monkeypatch.setattr(azure_inventory, "enumerate_subscription_ids", unexpected)
    monkeypatch.setattr(gcp_organizations, "list_project_ids", unexpected)
    with pytest.raises(CloudDiscoveryError, match="No .* resolved"):
        if provider == "azure":
            azure_cis_benchmark.run_all_subscription_benchmarks(credential=object(), subscription_ids=[])
        else:
            gcp_cis_benchmark.run_all_project_benchmarks(credentials=object(), project_ids=[])


@pytest.mark.parametrize("provider", ["azure", "gcp"])
def test_explicit_cis_scopes_are_deduplicated_bounded_and_attributed(monkeypatch, provider):
    from agent_bom.cloud import azure_cis_benchmark, azure_inventory, gcp_cis_benchmark, gcp_inventory
    from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult

    azure = provider == "azure"
    module = azure_cis_benchmark if azure else gcp_cis_benchmark
    key = "subscription_id" if azure else "project_id"
    report_class = module.AzureCISReport if azure else module.GCPCISReport
    monkeypatch.setattr(azure_inventory if azure else gcp_inventory, "_MAX_SUBSCRIPTIONS" if azure else "_MAX_PROJECTS", 2)

    def run(**kwargs):
        check = CISCheckResult(check_id="1.1", title="Scoped check", status=CheckStatus.PASS, severity="low", evidence="fixture")
        return report_class(**{key: kwargs[key]}, checks=[check])

    monkeypatch.setattr(module, "run_benchmark", run)
    ids = ["scope-c", " scope-a ", "scope-a", "scope-b"]
    report = (
        module.run_all_subscription_benchmarks(credential=object(), subscription_ids=ids)
        if azure
        else module.run_all_project_benchmarks(credentials=object(), project_ids=ids)
    )
    payload = report.to_dict()
    assert [check[key] for check in payload["checks"]] == ["scope-a", "scope-b"]
    assert any("capped at 2 of 3" in warning for warning in payload["warnings"])


@pytest.mark.parametrize("provider", ["azure", "gcp"])
def test_brokered_inventory_does_not_use_ambient_scope(monkeypatch, provider):
    from agent_bom.cloud import azure_inventory, gcp_inventory, gcp_organizations

    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "unrelated-ambient-subscription")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "unrelated-ambient-project")
    monkeypatch.setattr(azure_inventory, "_discover_management_groups", lambda credential: ([], []))
    monkeypatch.setattr(gcp_organizations, "list_project_ids", lambda *a, **k: [])
    if provider == "azure":
        ids, _ = azure_inventory.enumerate_subscription_ids(object(), allow_ambient_fallback=False)
        assert ids == []
    else:
        payloads = gcp_inventory.discover_all_project_inventories(credentials=object(), force=True, allow_ambient_fallback=False)
        assert payloads == []
