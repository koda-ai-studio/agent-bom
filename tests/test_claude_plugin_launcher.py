"""The directory entrypoint names a real bundled file and retains the locked launcher."""

import json
import os
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "integrations" / "claude-code"


def test_claude_server_names_a_bundled_entrypoint():
    servers = json.loads((PLUGIN / ".mcp.json").read_text())["mcpServers"]
    for name, spec in servers.items():
        assert spec["command"] == "python3"
        assert spec["args"][0] == "${CLAUDE_PLUGIN_ROOT}/mcp_launcher.py"
        assert spec["args"][1:] == (["--profile", "audit"] if name.endswith("audit") else [])
        assert (PLUGIN / "mcp_launcher.py").is_file()


def test_launcher_uses_its_own_project_and_preserves_arguments(monkeypatch, tmp_path):
    calls = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["mcp_launcher.py", "--profile", "audit"])
    monkeypatch.setattr(os, "execvp", lambda command, argv: calls.append((command, argv)))
    runpy.run_path(str(PLUGIN / "mcp_launcher.py"), run_name="__main__")
    assert calls == [
        ("uv", ["uv", "run", "--frozen", "--isolated", "--project", str(PLUGIN), "agent-bom", "mcp", "server", "--profile", "audit"])
    ]
