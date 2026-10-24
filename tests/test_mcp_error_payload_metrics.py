"""A tool that returns an error payload is logged and counted as a failure.

Tools commonly catch their own exceptions and return ``{"error": ...}`` or an
``mcp_error_json`` envelope. The dispatch layer must not log ``mcp tool ok`` or
record a success for those calls; metrics, the request trace and the log line
have to agree that the call failed.
"""

from __future__ import annotations

import json
import logging

import pytest

pytest.importorskip("mcp")

from agent_bom.mcp_errors import CODE_VALIDATION_INVALID_ARGUMENT, mcp_error_json  # noqa: E402
from agent_bom.mcp_server import (  # noqa: E402
    _execute_tool_async,
    _execute_tool_sync_async,
    _recent_tool_requests,
    _tool_metrics,
)
from agent_bom.mcp_server_runtime import ToolErrorPayload, tool_result_error  # noqa: E402

_ENVELOPE = mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "bad argument")


@pytest.fixture(autouse=True)
def _clean_metrics():
    _tool_metrics.clear()
    _recent_tool_requests.clear()
    yield
    _tool_metrics.clear()
    _recent_tool_requests.clear()


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (json.dumps({"error": "boom"}), "boom"),
        (json.dumps({"error": "boom"}, indent=2), "boom"),
        (_ENVELOPE, f"{CODE_VALIDATION_INVALID_ARGUMENT}: bad argument"),
        (ToolErrorPayload(json.dumps({"status": "incomplete"})), "error payload"),
        (json.dumps({"error": None, "data": [1]}), None),
        (json.dumps({"error": "", "data": [1]}), None),
        (json.dumps({"findings": [], "note": "error-free"}), None),
        (json.dumps([{"error": "x"}]), None),
        ("plain text result", None),
        ('{"not json', None),
        ({"error": "dict results are not inspected"}, None),
        (None, None),
    ],
)
def test_tool_result_error_detection(result, expected):
    assert tool_result_error(result) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [json.dumps({"error": "File not found"}), _ENVELOPE])
async def test_async_error_payload_is_recorded_as_failure(payload, caplog):
    async def _tool():
        return payload

    with caplog.at_level(logging.INFO, logger="agent_bom.mcp_server"):
        result = await _execute_tool_async("payload_tool", _tool)

    assert result == payload
    metrics = _tool_metrics["payload_tool"]
    assert metrics["failures"] == 1
    assert metrics["last_status"] == "error"
    assert metrics["last_error"]
    assert _recent_tool_requests[-1]["status"] == "error"
    messages = [r.getMessage() for r in caplog.records]
    assert not any(m.startswith("mcp tool ok") for m in messages)
    assert any(m.startswith("mcp tool returned error") for m in messages)


@pytest.mark.asyncio
async def test_sync_error_payload_is_recorded_as_failure(caplog):
    def _tool():
        return json.dumps({"error": "Correlation failed"})

    with caplog.at_level(logging.INFO, logger="agent_bom.mcp_server"):
        await _execute_tool_sync_async("payload_sync_tool", _tool)

    metrics = _tool_metrics["payload_sync_tool"]
    assert metrics["failures"] == 1
    assert metrics["last_status"] == "error"
    assert _recent_tool_requests[-1]["status"] == "error"
    assert not any(r.getMessage().startswith("mcp tool ok") for r in caplog.records)


@pytest.mark.asyncio
async def test_successful_result_is_still_ok(caplog):
    def _tool():
        return json.dumps({"servers": [], "error_count": 0})

    with caplog.at_level(logging.INFO, logger="agent_bom.mcp_server"):
        await _execute_tool_sync_async("ok_tool", _tool)

    metrics = _tool_metrics["ok_tool"]
    assert metrics["failures"] == 0
    assert metrics["last_status"] == "ok"
    assert _recent_tool_requests[-1]["status"] == "ok"
    assert any(r.getMessage().startswith("mcp tool ok") for r in caplog.records)
