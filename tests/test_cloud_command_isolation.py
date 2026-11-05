"""Provider commands must not read unrelated workstation MCP configuration."""

import json
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from agent_bom.cli import main


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp", "databricks", "snowflake", "huggingface", "ollama"])
def test_cloud_command_keeps_workstation_discovery_out_of_report(monkeypatch, tmp_path, provider):
    local = Mock(return_value=[])
    skills = Mock(return_value=[])
    cloud = Mock(return_value=([], ["Fixture collector could not complete."]))
    monkeypatch.setenv("AGENT_BOM_OFFLINE", "1")
    monkeypatch.setenv("AGENT_BOM_AUTO_UPDATE_DB", "0")
    monkeypatch.setattr("agent_bom.cli._cloud_sdk.providers_missing_sdk", lambda providers: [])
    monkeypatch.setattr("agent_bom.cli._cloud_group._active_cloud_target", lambda provider: None)
    monkeypatch.setattr("agent_bom.cli.agents.discover_all", local)
    monkeypatch.setattr("agent_bom.parsers.skills.discover_skill_files", skills)
    monkeypatch.setattr("agent_bom.cloud.discover_from_provider", cloud)
    monkeypatch.setattr("agent_bom.cli.agents.scan_pipeline.discovery.run_benchmarks", lambda *args, **kwargs: None)
    output = tmp_path / "report.json"
    result = CliRunner().invoke(main, ["cloud", provider, "--quiet", "-f", "json", "-o", str(output)])
    assert result.exit_code == 1, result.output
    local.assert_not_called()
    skills.assert_not_called()
    assert cloud.call_args.args[0] == provider
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["agents"] == []
    assert payload["scan_run"]["outcome"] in {"failed", "partial"}
    assert payload["posture_grade"] == "N/A"
