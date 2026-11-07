"""Report aliases do not duplicate canonical payload sections on disk or ingest."""

from agent_bom.api.models import PushPayload
from agent_bom.api.push_evidence import normalize_pushed_report
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
from agent_bom.output.json_fmt import to_json


def test_report_preserves_root_packages_compatibility():
    package = Package(name="example", version="1.0", ecosystem="pypi")
    report = AIBOMReport(
        agents=[Agent(name="test", agent_type=AgentType.CUSTOM, config_path="", mcp_servers=[MCPServer(name="test", packages=[package])])]
    )
    payload = to_json(report)
    assert payload["packages"] == payload["ai_bom_entities"]["packages"]
    assert payload["ai_bom_entities"]["packages"][0]["name"] == "example"
    assert payload["inventory_snapshot"]["packages"]  # Replay schema retains its separate contract.
    assert payload["agents"][0]["mcp_servers"][0]["packages"][0]["name"] == "example"


def test_ingest_normalizes_legacy_alias_once_and_preserves_distinct_sections():
    package = {"name": "example", "version": "1.0"}
    blast = {"vulnerability_id": "CVE-2024-1234", "package": "example@1.0", "severity": "high"}
    body = PushPayload.model_validate({"packages": [package], "ai_bom_entities": {"packages": [package]}, "blast_radii": [blast]})
    result = normalize_pushed_report(body, fallback_scan_id="test")
    assert result["packages"] == [package]
    assert "blast_radii" not in result
    assert result["blast_radius"] == [blast]
    assert result["ai_bom_entities"]["packages"] == [package]
    body = PushPayload.model_validate({"packages": [package], "ai_bom_entities": {"packages": [{"name": "different"}]}})
    assert normalize_pushed_report(body, fallback_scan_id="test")["packages"] == [package]


def test_compaction_preserves_the_bounded_graph_workspace_threshold(monkeypatch):
    from agent_bom.api.graph_persistence import _graph_store_backed_build_enabled
    from agent_bom.output.report_compaction import compact_report_sections

    monkeypatch.delenv("AGENT_BOM_GRAPH_STORE_BACKED_BUILD", raising=False)
    monkeypatch.setenv("AGENT_BOM_GRAPH_STORE_BACKED_MIN_ENTITIES", "5000")
    packages = [{"name": f"package-{n}", "version": "1"} for n in range(5000)]
    report = {"packages": packages, "ai_bom_entities": {"packages": packages}}
    assert _graph_store_backed_build_enabled(report)
    compact = compact_report_sections(report)
    assert compact["packages"] == packages
    assert _graph_store_backed_build_enabled(compact)
