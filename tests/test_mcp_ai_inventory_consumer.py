"""The dedicated MCP inventory tool retains package identity and redaction."""

import json

import pytest

from agent_bom.ai_components.models import AIComponent, AIComponentReport, AIComponentType
from agent_bom.mcp_tools.specialized import ai_inventory_scan_impl


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "filename,source,package,ecosystem",
    [
        ("agent.py", "from google.adk import Agent\n", "google-adk", "pypi"),
        ("plugin.ts", 'import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";\n', "openclaw", "npm"),
    ],
)
async def test_mcp_inventory_preserves_package_identity(tmp_path, monkeypatch, filename, source, package, ecosystem):
    monkeypatch.setattr("agent_bom.mcp_server_runtime.mcp_workspace_roots", lambda: [tmp_path])
    (tmp_path / filename).write_text(source)
    result = json.loads(await ai_inventory_scan_impl(directory=str(tmp_path), _truncate_response=lambda value: value))
    assert "error" not in result
    component = next(c for c in result["components"] if c.get("package") == package)
    assert component["ecosystem"] == ecosystem
    assert component["file"].endswith(filename)
    assert component["line"] == 1


@pytest.mark.asyncio
async def test_mcp_inventory_redacts_credential_names(tmp_path, monkeypatch):
    monkeypatch.setattr("agent_bom.mcp_server_runtime.mcp_workspace_roots", lambda: [tmp_path])
    report = AIComponentReport(
        components=[
            AIComponent(
                component_type=AIComponentType.API_KEY,
                name="sensitive-name-placeholder",
                language="python",
                file_path="agent.py",
                line_number=1,
                matched_text="sensitive-source-placeholder",
            )
        ]
    )
    monkeypatch.setattr("agent_bom.ai_components.scan_source", lambda *_args: report)
    text = await ai_inventory_scan_impl(directory=str(tmp_path), _truncate_response=lambda value: value)
    assert json.loads(text)["components"][0]["name"] == "[REDACTED]"
    assert "sensitive-name-placeholder" not in text
    assert "sensitive-source-placeholder" not in text
