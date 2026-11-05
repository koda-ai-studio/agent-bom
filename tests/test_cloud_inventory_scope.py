"""Cloud commands collect the selected estate without ambient provider fan-out."""

from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.models import AIBOMReport
from agent_bom.scan_enrichment import collect_cloud_inventory, enrich_report_with_estate_discovery


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_explicit_cloud_scope_collects_native_inventory_without_environment_flags(monkeypatch, provider):
    collectors = {}
    for name in ("aws", "azure", "gcp"):
        module = __import__("agent_bom.cloud." + name + "_inventory", fromlist=[""])
        monkeypatch.setattr(module, "inventory_enabled", lambda: False)
        collector = Mock(return_value={"provider": name, "status": "ok"})
        monkeypatch.setattr(module, "discover_inventory", collector)
        collectors[name] = collector
    results = collect_cloud_inventory(providers=(provider,), azure_subscription="selected", gcp_project="selected")
    assert results == [{"provider": provider, "status": "ok"}]
    assert collectors[provider].call_args.kwargs["force"] is True
    for name, collector in collectors.items():
        if name != provider:
            collector.assert_not_called()


def test_explicit_cloud_inventory_does_not_expand_to_ambient_identity_or_audit_sources(monkeypatch):
    monkeypatch.setattr("agent_bom.scan_enrichment.collect_cloud_inventory", lambda **kwargs: [])
    identity = Mock()
    audit = Mock()
    monkeypatch.setattr("agent_bom.scan_enrichment.collect_identity_discovery", identity)
    monkeypatch.setattr("agent_bom.scan_enrichment.collect_audit_trail", audit)
    enrich_report_with_estate_discovery(AIBOMReport(agents=[]), providers=("azure",))
    identity.assert_not_called()
    audit.assert_not_called()


def test_cloud_azure_retains_all_six_storage_accounts_in_report(monkeypatch, tmp_path):
    import json

    monkeypatch.setenv("AGENT_BOM_OFFLINE", "1")
    monkeypatch.setenv("AGENT_BOM_AUTO_UPDATE_DB", "0")
    monkeypatch.setattr("agent_bom.cli._cloud_sdk.providers_missing_sdk", lambda providers: [])
    monkeypatch.setattr("agent_bom.cloud.discover_from_provider", lambda *args, **kwargs: ([], []))
    monkeypatch.setattr("agent_bom.cli.agents.scan_pipeline.discovery.run_benchmarks", lambda *args, **kwargs: None)
    inventory = {
        "provider": "azure",
        "status": "ok",
        "account_id": "selected",
        "storage_accounts": [{"id": f"/subscriptions/selected/storage/account-{i}", "name": f"account-{i}"} for i in range(6)],
    }
    collector = Mock(return_value=inventory)
    monkeypatch.setattr("agent_bom.cloud.azure_inventory.discover_inventory", collector)
    output = tmp_path / "azure.json"
    result = CliRunner().invoke(main, ["cloud", "azure", "--subscription", "selected", "--quiet", "-f", "json", "-o", str(output)])
    assert output.exists(), result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert len(payload["cloud_inventory"][0]["storage_accounts"]) == 6
    assert collector.call_args.kwargs == {"subscription_id": "selected", "force": True}


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_requested_inventory_exception_retains_incomplete_receipt(monkeypatch, provider):
    module = __import__("agent_bom.cloud." + provider + "_inventory", fromlist=[""])
    monkeypatch.setattr(module, "discover_inventory", Mock(side_effect=RuntimeError("fixture-private-detail")))
    result = collect_cloud_inventory(providers=(provider,))
    assert len(result) == 1
    assert result[0]["provider"] == provider
    assert result[0]["status"] == "error"
    assert result[0]["completeness"] == "partial"
    assert "fixture-private-detail" not in str(result)
