"""Bad or empty input must produce the MCP error envelope, never a silent default."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest


def _error(raw: str) -> dict:
    payload = json.loads(raw)
    assert isinstance(payload.get("error"), dict), payload
    return payload["error"]


@pytest.mark.asyncio
async def test_generate_sbom_rejects_unknown_format_before_scanning() -> None:
    from agent_bom.mcp_tools.sbom import generate_sbom_impl

    pipeline = AsyncMock()
    error = _error(await generate_sbom_impl(format="bogus", _run_scan_pipeline=pipeline, _truncate_response=lambda s: s))
    assert error["code"] == "AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT"
    assert error["details"]["argument"] == "format"
    assert "cyclonedx" in error["message"] and "spdx" in error["message"]
    pipeline.assert_not_called()


@pytest.mark.asyncio
async def test_compliance_rejects_unknown_framework() -> None:
    from agent_bom.mcp_tools.compliance_persisted import compliance_tool_impl

    pipeline = AsyncMock()
    error = _error(await compliance_tool_impl(framework="bogus", source="local_scan", _run_scan_pipeline=pipeline))
    assert error["code"] == "AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT"
    assert error["details"]["argument"] == "framework"
    assert "soc2" in error["message"]
    pipeline.assert_not_called()


@pytest.mark.asyncio
async def test_compliance_local_scan_says_framework_was_not_applied(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.mcp_tools import compliance_persisted

    async def _local(**_kw):
        return json.dumps({"overall_score": 100})

    monkeypatch.setattr(compliance_persisted, "compliance_impl", _local)
    result = json.loads(
        await compliance_persisted.compliance_tool_impl(framework="SOC2", source="local_scan", _run_scan_pipeline=AsyncMock())
    )
    assert result["source"] == "local_scan"
    assert any("framework" in w and "persisted" in w for w in result["warnings"])


def test_inventory_missing_path_is_an_invalid_path_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.mcp_tools.runtime import inventory_impl

    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda **_kw: pytest.fail("must not discover a missing path"))
    error = _error(inventory_impl(config_path=str(tmp_path / "does-not-exist"), _truncate_response=lambda s: s))
    assert error["code"] == "AGENTBOM_MCP_VALIDATION_INVALID_PATH"
    assert "does not exist" in error["message"]


@pytest.mark.asyncio
async def test_prompt_scan_of_zero_files_is_not_a_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.mcp_tools.specialized import prompt_scan_impl

    monkeypatch.setenv("AGENT_BOM_MCP_WORKSPACE_ROOTS", str(tmp_path))
    error = _error(await prompt_scan_impl(directory=str(tmp_path), _truncate_response=lambda s: s))
    assert error["code"] == "AGENTBOM_MCP_NOT_FOUND_RESOURCE"
    assert "nothing was scanned" in error["message"].lower()
    assert error["details"]["files_scanned"] == 0
