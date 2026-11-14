"""Container evidence survives presentation and partial extraction failures."""

import json
from unittest.mock import AsyncMock

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.models import Agent, AgentType, MCPServer, Package
from agent_bom.output.report_packing import load_report_document
from agent_bom.security import sanitize_sensitive_payload

IMAGE = "python:3.11.4-alpine3.18@sha256:603975e62d85aa07578034d3d10ffa1983b7618a6abb6371cf51941be6b8842c"


@pytest.mark.parametrize("key", ["name", "image", "image_ref", "label", "node_ids"])
def test_digest_image_identity_survives_structured_redaction(key):
    assert sanitize_sensitive_payload({key: IMAGE}) == {key: IMAGE}


def test_image_shape_does_not_exempt_secrets():
    token = "ghp_" + "X" * 36
    assert token not in str(sanitize_sensitive_payload({"name": token + "/" + IMAGE}))
    assert sanitize_sensitive_payload({"password": IMAGE}) == {"password": "***REDACTED***"}


def test_failed_docker_server_keeps_healthy_inventory_and_partial_report(tmp_path, monkeypatch):
    from agent_bom.image import ImageScanError

    healthy = Package(name="six", version="1.17.0", ecosystem="pypi")
    agent = Agent(
        name="fixture",
        agent_type=AgentType.CUSTOM,
        config_path="fixture.json",
        mcp_servers=[
            MCPServer(name="healthy", command="npx"),
            MCPServer(name="broken", command="docker", args=["run", "fixture/image:1"]),
        ],
    )
    monkeypatch.setattr("agent_bom.cli.agents.discover_all", lambda *a, **k: [agent])
    monkeypatch.setattr(
        "agent_bom.cli.agents.extract_packages",
        lambda server, **k: [healthy] if server.name == "healthy" else [Package(name="fixture/image", version="1", ecosystem="docker")],
    )
    monkeypatch.setattr("agent_bom.cli.agents.scan_agents_sync", lambda *a, **k: [])
    monkeypatch.setattr("agent_bom.enrichment.fetch_cisa_kev_catalog", AsyncMock(return_value={}))

    def fail(*args, **kwargs):
        raise ImageScanError("fixture image unavailable")

    monkeypatch.setattr("agent_bom.image.scan_image", fail)
    output = tmp_path / "report.json"
    result = CliRunner().invoke(main, ["scan", "--offline", "--no-auto-update-db", "--no-skill", "-f", "json", "-o", str(output)])
    assert result.exit_code == 1, result.output
    payload = load_report_document(json.loads(output.read_text()))
    assert payload["scan_run"]["outcome"] == "partial"
    assert payload["posture_grade"] == "N/A"
    assert any(p["name"] == "six" for a in payload["agents"] for s in a["mcp_servers"] for p in s["packages"])
    assert any("Docker" in i["message"] for i in payload["scan_run"]["issues"])
