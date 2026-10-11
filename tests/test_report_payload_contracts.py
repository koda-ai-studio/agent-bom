"""Report extension annotations describe producer payloads without rewriting them."""

from typing import get_type_hints

import pytest
from pydantic import TypeAdapter, ValidationError

from agent_bom import models
from agent_bom.models import AIBOMReport
from agent_bom.vuln_freshness import VulnDataFreshness


def contract_for(field):
    contract = type("ReportField", (), {"__annotations__": {"payload": AIBOMReport.__annotations__[field]}})
    return TypeAdapter(get_type_hints(contract, vars(models))["payload"])


def test_freshness_contract_rejects_invalid_nested_counter():
    payload = VulnDataFreshness(mode="offline").to_dict()
    payload["age_hours"] = "unknown"
    contract = contract_for("vuln_data_freshness")
    with pytest.raises(ValidationError):
        contract.validate_python(payload, strict=True)


def test_runtime_contract_rejects_string_count():
    from agent_bom.runtime_correlation import CorrelationReport

    payload = CorrelationReport(0, 0, 0, [], []).to_dict()
    payload["total_tool_calls"] = "zero"
    contract = contract_for("runtime_correlation")
    with pytest.raises(ValidationError):
        contract.validate_python(payload, strict=True)


@pytest.mark.parametrize(
    "field",
    ["cis_benchmark_data", "azure_cis_benchmark_data", "gcp_cis_benchmark_data", "snowflake_cis_benchmark_data", "aisvs_benchmark_data"],
)
def test_benchmark_contract_rejects_untyped_check(field):
    payload = {
        "benchmark": "fixture",
        "benchmark_version": "1",
        "passed": 0,
        "failed": 0,
        "total": 1,
        "pass_rate": 0.0,
        "checks": [
            {
                "check_id": "1",
                "title": "test",
                "status": "error",
                "severity": "high",
                "evidence": 99,
                "recommendation": "inspect",
                "cis_section": "1",
            }
        ],
    }
    with pytest.raises(ValidationError):
        contract_for(field).validate_python(payload, strict=True)


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp", "snowflake", "aisvs"])
def test_benchmark_producers_keep_nested_evidence_and_export(provider):
    from agent_bom.cloud.aisvs_benchmark import AIVSReport
    from agent_bom.cloud.aws_cis._base import CheckStatus, CISBenchmarkReport, CISCheckResult
    from agent_bom.cloud.azure_cis._base import AzureCISReport
    from agent_bom.cloud.gcp_cis._base import GCPCISReport
    from agent_bom.cloud.snowflake_cis_benchmark import SnowflakeCISReport
    from agent_bom.output.json_fmt import to_json

    report_class, field, output_key = {
        "aws": (CISBenchmarkReport, "cis_benchmark_data", "cis_benchmark"),
        "azure": (AzureCISReport, "azure_cis_benchmark_data", "azure_cis_benchmark"),
        "gcp": (GCPCISReport, "gcp_cis_benchmark_data", "gcp_cis_benchmark"),
        "snowflake": (SnowflakeCISReport, "snowflake_cis_benchmark_data", "snowflake_cis_benchmark"),
        "aisvs": (AIVSReport, "aisvs_benchmark_data", "aisvs_benchmark"),
    }[provider]
    check = CISCheckResult("1.1", "Fixture control", CheckStatus.ERROR, "high", evidence="Read permission denied")
    payload = report_class(checks=[check]).to_dict()
    assert contract_for(field).validate_python(payload, strict=True) == payload
    report = AIBOMReport(**{field: payload})
    rendered = to_json(report)[output_key]
    expected = {**payload, "checks": [dict(row) for row in payload["checks"]]}
    if provider != "aisvs":
        # Existing export boundary strips executable remediation from ERROR evidence.
        expected["checks"][0]["remediation"] = {"fix_cli": None, "effort": "manual", "requires_human_review": True}
    assert rendered == expected
    assert contract_for(field).validate_python(rendered, strict=True) == rendered


def test_freshness_cache_and_runtime_payload_round_trip():
    from agent_bom.output.json_fmt import to_json
    from agent_bom.runtime_correlation import CorrelatedFinding, CorrelationReport

    freshness = VulnDataFreshness(mode="live").to_dict(osv_performance={"cache_hits": 3, "queries_sent": 2})
    finding = CorrelatedFinding(
        "CVE-2026-0001",
        "high",
        8.0,
        0.3,
        False,
        "fixture",
        "1",
        "read",
        "server",
        2,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00Z",
        False,
        1.2,
        5.0,
        6.0,
    )
    correlation = CorrelationReport(2, 1, 1, [finding], []).to_dict()
    assert contract_for("vuln_data_freshness").validate_python(freshness, strict=True) == freshness
    assert contract_for("runtime_correlation").validate_python(correlation, strict=True) == correlation
    report = AIBOMReport(vuln_data_freshness=freshness, runtime_correlation=correlation)
    rendered = to_json(report)
    assert rendered["vuln_data_freshness"] == freshness
    assert rendered["runtime_correlation"] == correlation


def test_license_and_vex_producers_preserve_unknown_and_nullable_evidence():
    from agent_bom.license_policy import LicenseReport
    from agent_bom.license_policy import to_serializable as license_payload
    from agent_bom.output.json_fmt import to_json
    from agent_bom.vex import VexDocument, VexStatement, VexStatus
    from agent_bom.vex import to_serializable as vex_payload

    licenses = license_payload(LicenseReport(compliant=False, status="undetermined", total_packages=1, unknown_count=1))
    vex = vex_payload(VexDocument(statements=[VexStatement("CVE-2026-0001", VexStatus.UNDER_INVESTIGATION)]))
    assert contract_for("license_report").validate_python(licenses, strict=True) == licenses
    assert contract_for("vex_data").validate_python(vex, strict=True) == vex
    rendered = to_json(AIBOMReport(license_report=licenses, vex_data=vex))
    assert rendered["license_report"] == licenses
    assert rendered["vex"] == vex


def test_evaluated_license_findings_and_coverage_round_trip():
    from agent_bom.license_policy import evaluate_license_policy, to_serializable
    from agent_bom.models import Agent, AgentType, MCPServer, Package

    agent = Agent(
        name="fixture",
        agent_type=AgentType.CUSTOM,
        config_path="",
        mcp_servers=[
            MCPServer(
                name="packages",
                command="",
                packages=[
                    Package(name="unknown", version="1", ecosystem="npm"),
                    Package(name="copyleft", version="1", ecosystem="npm", license="AGPL-3.0-only"),
                ],
            )
        ],
    )
    payload = to_serializable(evaluate_license_policy([agent]))
    assert payload["findings"]
    assert payload["unknown_count"] == 1
    assert payload["summary"]["by_category"]
    assert contract_for("license_report").validate_python(payload, strict=True) == payload
