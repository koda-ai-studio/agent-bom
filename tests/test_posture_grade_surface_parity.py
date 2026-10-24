"""One posture grade: the MCP scan must grade the same evidence the CLI grades.

The CLI folds scanner warnings that affect vulnerability coverage into
``scan_run`` before computing the scorecard. The MCP scan used to drop them,
so the same project graded "C" over MCP and "N/A" on the CLI.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import patch

import pytest

pytest.importorskip("mcp")

from mcp import Client  # noqa: E402

from tests.test_mcp_scan_tool_contract import _one_agent  # noqa: E402

_WARNING = "Some local advisory ranges cannot be verified."


def _scan_body() -> dict[str, Any]:
    from agent_bom.mcp_server import create_mcp_server

    async def _pipeline(*_a, **_k):
        from agent_bom.scanners.state import record_scan_warning

        record_scan_warning(_WARNING)
        return [_one_agent()], [], [], ["agent_discovery"]

    async def _run() -> Any:
        async with Client(create_mcp_server(profile="full")) as client:
            return await client.call_tool("scan", {"no_discover": True, "offline": True})

    with patch("agent_bom.mcp_server._run_scan_pipeline", side_effect=_pipeline):
        result = asyncio.run(_run())
    return json.loads(result.content[0].text)


def test_mcp_scan_grades_scanner_coverage_warnings_like_the_cli() -> None:
    from agent_bom.evidence.scan_run import ScanRun, scanner_warning_issues
    from agent_bom.models import AIBOMReport
    from agent_bom.posture import compute_posture_scorecard

    body = _scan_body()
    cli_like = AIBOMReport([_one_agent()], [], scan_run=ScanRun(issues=scanner_warning_issues([_WARNING])))
    expected = compute_posture_scorecard(cli_like).grade
    assert expected == "N/A"
    assert body["posture_grade"] == expected
    assert body["posture"]["grade"] == expected
    assert _WARNING in body["warnings"]
