"""Native provider evidence must retain collection gaps through report serialization."""

import json
from copy import deepcopy

import pytest

from agent_bom.evidence.scan_run import ScanIssue, ScanOutcome, effective_scan_run
from agent_bom.models import AIBOMReport
from agent_bom.output import to_json


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_native_inventory_warning_makes_serialized_report_partial(provider):
    inventory = {"provider": provider, "status": "ok", "warnings": ["Denied https://private.example/?token=secret"]}
    report = AIBOMReport(agents=[], blast_radii=[], cloud_inventory_data=inventory)
    result = to_json(report)
    assert result["scan_run"]["outcome"] == "partial"
    assert result["scan_run"]["incomplete_scope_count"] == 1
    assert "private.example" not in str(result["scan_run"])
    assert report.scan_run.outcome == ScanOutcome.COMPLETE  # serialization is non-mutating


@pytest.mark.parametrize(
    "provider,field", [("aws", "cis_benchmark_data"), ("azure", "azure_cis_benchmark_data"), ("gcp", "gcp_cis_benchmark_data")]
)
@pytest.mark.parametrize("gap", [{"errored": 1}, {"no_data": 1}, {"completeness": "partial"}])
def test_native_benchmark_gaps_are_partial(provider, field, gap):
    report = AIBOMReport(agents=[], blast_radii=[], **{field: {"failed": 5, **gap}})
    run = effective_scan_run(report)
    assert run.outcome == ScanOutcome.PARTIAL
    assert run.scopes[0].name == f"cloud:{provider}:posture"


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_one_denied_account_cannot_be_hidden_by_a_complete_account(provider):
    payloads = [
        {"provider": provider, "status": "ok", "account_id": "account-a"},
        {"provider": provider, "status": "permission_denied", "account_id": "account-b"},
    ]
    report = AIBOMReport(agents=[], blast_radii=[], cloud_inventory_data=payloads)
    before = deepcopy(payloads)
    run = effective_scan_run(report)
    assert run.outcome == ScanOutcome.PARTIAL
    assert run.scopes[0].status.value == "permission_denied"
    assert report.cloud_inventory_data == before


def test_complete_collection_with_failed_controls_is_still_complete_execution():
    report = AIBOMReport(
        agents=[],
        blast_radii=[],
        cloud_inventory_data={"provider": "aws", "status": "ok"},
        cis_benchmark_data={"failed": 40, "errored": 0, "no_data": 0},
    )
    run = effective_scan_run(report)
    assert run.outcome == ScanOutcome.COMPLETE
    assert len(run.scopes) == 2
    assert all(scope.status.value == "complete" for scope in run.scopes)


def test_inventory_missing_permissions_and_repeated_projection_preserve_failure():
    report = AIBOMReport(
        agents=[], blast_radii=[], cloud_inventory_data={"provider": "gcp", "status": "ok", "missing_permissions": [{"permission": "read"}]}
    )
    report.scan_run.mark_failed()
    report.scan_run.add_issue(ScanIssue(code="existing", stage="discovery", source="test", message="existing issue"))
    first = effective_scan_run(report)
    report.scan_run = first
    assert effective_scan_run(report).to_dict() == first.to_dict()
    assert first.outcome == ScanOutcome.FAILED
    assert first.scopes[0].status.value == "permission_denied"


def test_cli_and_api_summary_preserve_native_collection_gaps(monkeypatch):
    from click.testing import CliRunner

    from agent_bom.cli._cloud_group import inventory_cmd
    from agent_bom.cloud import aws_inventory
    from agent_bom.cloud.inventory_summary import _summarize_inventory_payload

    payload = {"provider": "aws", "status": "ok", "warnings": ["Denied"], "buckets": []}
    monkeypatch.setattr(aws_inventory, "discover_inventory", lambda **kwargs: payload)
    result = CliRunner().invoke(inventory_cmd, ["--provider", "aws", "-f", "json"])
    assert result.exit_code == 0
    assert json.loads(result.output)["scan_run"]["outcome"] == "partial"
    assert _summarize_inventory_payload("aws", payload)["status"] == "partial"


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_ingest_derives_partial_from_native_evidence_even_if_producer_claims_complete(provider):
    from agent_bom.api.push_models import normalize_push_coverage

    report = {"scan_run": {"outcome": "complete"}, "cloud_inventory": [{"provider": provider, "status": "ok", "warnings": ["Denied"]}]}
    normalized = normalize_push_coverage(report, source_id="runner", target_scope="v1:" + "a" * 64)
    assert normalized["scan_run"]["outcome"] == "partial"
