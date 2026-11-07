"""Report aliases do not duplicate canonical payload sections on disk or ingest."""

from agent_bom.api.models import PushPayload
from agent_bom.api.push_evidence import normalize_pushed_report
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
from agent_bom.output.json_fmt import to_json


def test_report_keeps_one_flat_entity_package_table():
    package = Package(name="example", version="1.0", ecosystem="pypi")
    report = AIBOMReport(
        agents=[Agent(name="test", agent_type=AgentType.CUSTOM, config_path="", mcp_servers=[MCPServer(name="test", packages=[package])])]
    )
    payload = to_json(report)
    assert "packages" not in payload
    assert payload["ai_bom_entities"]["packages"][0]["name"] == "example"
    assert payload["inventory_snapshot"]["packages"]  # Replay schema retains its separate contract.
    assert payload["agents"][0]["mcp_servers"][0]["packages"][0]["name"] == "example"


def test_ingest_normalizes_legacy_alias_once_and_preserves_distinct_sections():
    package = {"name": "example", "version": "1.0"}
    blast = {"vulnerability_id": "CVE-2024-1234", "package": "example@1.0", "severity": "high"}
    body = PushPayload.model_validate({"packages": [package], "ai_bom_entities": {"packages": [package]}, "blast_radii": [blast]})
    result = normalize_pushed_report(body, fallback_scan_id="test")
    assert "packages" not in result
    assert "blast_radii" not in result
    assert result["blast_radius"] == [blast]
    assert result["ai_bom_entities"]["packages"] == [package]
    body = PushPayload.model_validate({"packages": [package], "ai_bom_entities": {"packages": [{"name": "different"}]}})
    assert normalize_pushed_report(body, fallback_scan_id="test")["packages"] == [package]
