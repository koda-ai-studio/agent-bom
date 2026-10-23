"""Every MCP tool that takes a filesystem path reports a sandbox rejection the same way.

A path outside HOME and ``AGENT_BOM_MCP_WORKSPACE_ROOTS`` must come back as an
``isError`` result carrying ``AGENTBOM_MCP_VALIDATION_INVALID_PATH``, the
argument name and the setting that widens the sandbox — never a generic
"internal error" and never a success-shaped payload.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp")

from mcp import Client  # noqa: E402
from mcp_types import CallToolResult  # noqa: E402

from agent_bom.mcp_errors import CODE_VALIDATION_INVALID_PATH  # noqa: E402


def _call(tool: str, args: dict[str, Any]) -> CallToolResult:
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server(profile="full")

    async def _run() -> CallToolResult:
        async with Client(server) as client:
            return await client.call_tool(tool, args)

    return asyncio.run(_run())


@pytest.fixture()
def outside_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / ".mcp.json").write_text('{"mcpServers": {}}')
    (outside / "SKILL.md").write_text("# skill\n")
    (outside / "audit.jsonl").write_text("")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("AGENT_BOM_MCP_WORKSPACE_ROOTS", raising=False)
    return outside


_CASES = [
    ("tool_risk_assessment", "config_path", {"live": False}, ""),
    ("scan", "config_path", {"offline": True}, ""),
    ("code_scan", "path", {}, ""),
    ("skill_trust", "skill_path", {}, "SKILL.md"),
    ("skill_scan", "path", {}, ""),
    ("skill_verify", "path", {}, ""),
    ("dataset_card_scan", "directory", {}, ""),
    ("training_pipeline_scan", "directory", {}, ""),
    ("prompt_scan", "directory", {}, ""),
    ("model_file_scan", "directory", {}, ""),
    ("ai_inventory_scan", "directory", {}, ""),
]


@pytest.mark.parametrize(("tool", "argument", "extra", "leaf"), _CASES, ids=[c[0] for c in _CASES])
def test_out_of_sandbox_path_is_a_structured_validation_error(
    outside_dir: Path, tool: str, argument: str, extra: dict[str, Any], leaf: str
) -> None:
    target = outside_dir / leaf if leaf else outside_dir
    result = _call(tool, {argument: str(target), **extra})

    text = result.content[0].text  # type: ignore[union-attr]
    assert result.is_error, text
    assert CODE_VALIDATION_INVALID_PATH in text
    assert f"(argument: {argument})" in text
    assert "AGENT_BOM_MCP_WORKSPACE_ROOTS" in text
    assert "internal error" not in text.lower()
    assert str(outside_dir) not in text


def test_runtime_correlate_audit_log_outside_sandbox(outside_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def _no_scan(*_args: Any, **_kwargs: Any) -> tuple[list, list, list, list]:
        return [], [], [], []

    monkeypatch.setattr("agent_bom.mcp_server._run_scan_pipeline", _no_scan)
    result = _call("runtime_correlate", {"audit_log": str(outside_dir / "audit.jsonl")})

    text = result.content[0].text  # type: ignore[union-attr]
    assert result.is_error, text
    assert CODE_VALIDATION_INVALID_PATH in text
    assert "(argument: audit_log)" in text
    assert "AGENT_BOM_MCP_WORKSPACE_ROOTS" in text


def test_inside_home_path_is_still_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    (home / "proj").mkdir(parents=True)
    (home / "proj" / ".mcp.json").write_text('{"mcpServers": {}}')
    monkeypatch.setenv("HOME", str(home))
    result = _call("tool_risk_assessment", {"config_path": str(home / "proj"), "live": False})

    text = result.content[0].text  # type: ignore[union-attr]
    assert not result.is_error, text
    assert CODE_VALIDATION_INVALID_PATH not in text
