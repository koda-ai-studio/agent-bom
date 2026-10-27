"""Metadata changes under stable tool names must produce drift alerts."""

import asyncio
import copy

import pytest

from agent_bom.runtime.proxy_relay import ServerMessage, track_declared_tools
from tests.test_proxy_tool_catalog_paging import _session


def _feed(session, tools, cursor=None):
    result = {"tools": tools}
    if cursor is not None:
        result["nextCursor"] = cursor
    asyncio.run(track_declared_tools(session, ServerMessage(msg={"id": 1, "result": result}, line=b"")))


@pytest.mark.parametrize(
    "field,value", [("description", "changed private text"), ("inputSchema", {"type": "object", "required": ["path"]})]
)
def test_definition_changes_raise_high_alert_without_values(field, value):
    session, alerts = _session()
    original = {"name": "read", "description": "original private text", "inputSchema": {"type": "object"}}
    _feed(session, [original])
    changed = dict(original, **{field: value})
    _feed(session, [changed])
    assert len(alerts) == 1
    assert alerts[0].severity.value == "high"
    assert alerts[0].details["changed_tools"] == [{"name": "read", "fields": [field]}]
    assert "private text" not in str(alerts[0].to_dict())
    assert "required" not in str(alerts[0].to_dict())


def test_schema_key_order_and_tools_order_do_not_drift():
    session, alerts = _session()
    tools = [{"name": "a", "inputSchema": {"type": "object", "properties": {"b": {"type": "string"}, "a": {}}}}, {"name": "b"}]
    _feed(session, tools)
    changed = copy.deepcopy(tools)
    changed[0]["inputSchema"] = {"properties": {"a": {}, "b": {"type": "string"}}, "type": "object"}
    _feed(session, list(reversed(changed)))
    assert alerts == []


def test_definition_changes_on_later_page_are_detected():
    session, alerts = _session()
    _feed(session, [{"name": "a"}], "next")
    _feed(session, [{"name": "b", "description": "before"}])
    _feed(session, [{"name": "a"}], "next")
    _feed(session, [{"name": "b", "description": "after"}])
    assert alerts[0].details["changed_tools"] == [{"name": "b", "fields": ["description"]}]


def test_partial_catalog_does_not_establish_definition_baseline():
    session, alerts = _session()
    _feed(session, [{"name": "a", "description": "incomplete"}], 123)
    session.tool_catalog.note_request({"id": 1, "method": "tools/list"})
    _feed(session, [{"name": "a", "description": "complete"}])
    _feed(session, [{"name": "a", "description": "changed"}])
    assert len(alerts) == 1
    assert alerts[0].details["changed_tools"][0]["fields"] == ["description"]


@pytest.mark.asyncio
async def test_list_changed_requests_catalog_without_consuming_notification(monkeypatch):
    import io
    import json
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    from agent_bom.runtime import proxy_relay

    session, _alerts = _session()
    session.metrics.total_messages_server_to_client = 0
    session.process = SimpleNamespace(stdin=SimpleNamespace(write=Mock(), drain=AsyncMock()))
    output = io.BytesIO()
    notification = {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
    monkeypatch.setattr(proxy_relay, "SERVER_MESSAGE_STAGES", ())
    with monkeypatch.context() as scoped:
        scoped.setattr(proxy_relay.sys, "stdout", SimpleNamespace(buffer=output))
        await proxy_relay.relay_server_line(session, (json.dumps(notification) + "\n").encode())
    assert session.process.stdin.write.call_count == 1
    request = json.loads(session.process.stdin.write.call_args.args[0])
    assert request["method"] == "tools/list"
    assert json.loads(output.getvalue()) == notification


@pytest.mark.parametrize(
    "tool",
    [None, {"name": ""}, {"name": "a", "inputSchema": []}, {"name": "a", "description": 1}, {"name": "a", "description": "x" * 262145}],
)
def test_invalid_definition_cannot_establish_baseline(tool):
    session, _alerts = _session()
    _feed(session, [tool])
    assert session.detectors.drift.baseline is None


def test_tool_count_cap_does_not_establish_baseline():
    from agent_bom.runtime.drift_baseline import MAX_TOOL_DEFINITIONS

    session, _alerts = _session()
    _feed(session, [{"name": str(n)} for n in range(MAX_TOOL_DEFINITIONS + 1)])
    assert session.detectors.drift.baseline is None


@pytest.mark.asyncio
async def test_refresh_pages_detect_drift_and_do_not_mix_with_client_pages():
    import json
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    session, alerts = _session()
    _tools = [{"name": "a", "description": "before"}, {"name": "b"}]
    # Establish baseline without nesting asyncio.run inside the active loop.
    await track_declared_tools(session, ServerMessage(msg={"id": 1, "result": {"tools": _tools}}, line=b""))
    session.process = SimpleNamespace(stdin=SimpleNamespace(write=Mock(), drain=AsyncMock()))
    refresh = session.catalog_refresh
    assert not await refresh.inspect(session, {"method": "notifications/tools/list_changed"})
    request = json.loads(session.process.stdin.write.call_args.args[0])
    assert await refresh.inspect(
        session, {"id": request["id"], "result": {"tools": [{"name": "a", "description": "after"}], "nextCursor": ""}}
    )
    request = json.loads(session.process.stdin.write.call_args.args[0])
    assert request["params"] == {"cursor": ""}
    # A normal client's result is not consumed by the internal request path.
    assert not await refresh.inspect(session, {"id": 2, "result": {"tools": [{"name": "unrelated"}]}})
    assert await refresh.inspect(session, {"id": request["id"], "result": {"tools": [{"name": "b"}]}})
    assert alerts[0].details["changed_tools"] == [{"name": "a", "fields": ["description"]}]
    assert len(alerts) == 1
    assert refresh.request_id is None and refresh.deadline is None


@pytest.mark.asyncio
async def test_notifications_coalesce_and_failures_keep_the_baseline():
    import json
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    session, alerts = _session()
    session.detectors.drift.set_baseline(["a"])
    session.process = SimpleNamespace(stdin=SimpleNamespace(write=Mock(), drain=AsyncMock()))
    refresh = session.catalog_refresh
    for _ in range(10):
        await refresh.inspect(session, {"method": "notifications/tools/list_changed"})
    assert session.process.stdin.write.call_count == 1
    request = json.loads(session.process.stdin.write.call_args.args[0])
    await refresh.inspect(session, {"id": request["id"], "error": {"message": "private text"}})
    assert session.detectors.drift.baseline == {"a"}
    assert alerts[0].details == {"catalog_complete": False, "reason_code": "tool_catalog_incomplete"}
    assert "private text" not in str(alerts[0].to_dict())
    assert refresh.deadline is None
    # Late responses to proxy-owned requests must not leak into client traffic.
    assert await refresh.inspect(session, {"id": request["id"], "result": {"tools": []}})


@pytest.mark.asyncio
async def test_timeout_is_incomplete_and_close_cancels_deadline():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    session, alerts = _session()
    session.process = SimpleNamespace(stdin=SimpleNamespace(write=Mock(), drain=AsyncMock()))
    refresh = session.catalog_refresh
    await refresh.inspect(session, {"method": "notifications/tools/list_changed"})
    deadline = refresh.deadline
    await refresh._incomplete(session)
    assert deadline.cancelled()
    assert alerts[0].details["catalog_complete"] is False
    await refresh.inspect(session, {"method": "notifications/tools/list_changed"})
    deadline = refresh.deadline
    refresh.close()
    assert deadline.cancelled() and refresh.request_id is None


def test_persisted_alert_retains_structural_change_evidence():
    from agent_bom.evidence import EvidenceTier, redact_for_persistence

    session, alerts = _session()
    _feed(session, [{"name": "read", "description": "private before"}])
    _feed(session, [{"name": "read", "description": "private after"}])
    record = redact_for_persistence(alerts[0].to_dict(), EvidenceTier.SAFE_TO_STORE)
    assert record["details"]["tool_name"] == "read"
    assert record["details"]["reason_code"] == "tool_description_changed"
    assert "private" not in str(record)
