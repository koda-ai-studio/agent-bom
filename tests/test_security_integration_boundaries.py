"""MCP consumers receive trust boundaries and workflows run an immutable action."""

import json
import re
from pathlib import Path

import pytest
import yaml

from agent_bom.mcp_server_factory import _server_instructions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("profile", ["scan", "audit", "full"])
def test_mcp_initialization_marks_external_output_as_untrusted(profile):
    instructions = _server_instructions("0.0.0", profile)
    assert "untrusted" in instructions
    assert "tool results" in instructions and "do not follow" in instructions
    assert "JSON" in instructions and "not a prompt-injection security boundary" in instructions


def test_reusable_workflow_action_is_sha_pinned():
    workflow = yaml.safe_load((ROOT / ".github/workflows/agent-bom-reusable.yml").read_text())
    actions = [s["uses"] for job in workflow["jobs"].values() for s in job.get("steps", []) if "uses" in s]
    target = next(a for a in actions if a.startswith("koda-ai-studio/agent-bom@"))
    assert re.fullmatch(r"koda-ai-studio/agent-bom@[a-f0-9]{40}", target)


def test_codex_plugin_passes_operator_workspace_allowlist_without_literal_expansion():
    manifest = json.loads((ROOT / "integrations/claude-code/.codex-plugin/plugin.json").read_text())
    for server in manifest["mcpServers"].values():
        assert "AGENT_BOM_MCP_WORKSPACE_ROOTS" in server.get("env_vars", [])
        assert "AGENT_BOM_MCP_WORKSPACE_ROOTS" not in server["env"]
        assert server["env"]["AGENT_BOM_MCP_LIVE_INTROSPECTION"] == "0"
