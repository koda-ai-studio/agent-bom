"""`agent-bom proxy --url` over MCP Streamable HTTP, against a fixture upstream.

The fixture is an ``httpx.MockTransport`` that plays a Streamable HTTP MCP
server on one endpoint: it issues an ``Mcp-Session-Id`` on ``initialize``,
answers JSON or SSE, and records every request so the tests can assert on
what the proxy actually sent.
"""

from __future__ import annotations

import asyncio
import io
import json
from types import SimpleNamespace
from typing import Any, Callable
from unittest.mock import AsyncMock

import httpx
import pytest

from agent_bom import proxy
from agent_bom.runtime import mcp_protocol, proxy_upstream

BASE = "https://upstream.example.test/mcp"
SESSION = "sess-0f9c2b1e"
_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _call(msg_id: int, tool: str, arguments: dict | None = None) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "method": "tools/call", "params": {"name": tool, "arguments": arguments or {}}}


def _sse(*events: dict, prefix: str = ": keepalive\n\n") -> str:
    return prefix + "".join("event: message\ndata: " + json.dumps(e) + "\n\n" for e in events)


class FixtureServer:
    """Streamable HTTP MCP fixture with an overridable tools/call answer."""

    def __init__(self, *, session_id: str | None = SESSION, call_answer: Callable[[dict], httpx.Response] | None = None) -> None:
        self.session_id = session_id
        self.call_answer = call_answer
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.method == "DELETE":
            return httpx.Response(204)
        body = json.loads(request.content)
        method = body.get("method")
        if method == "initialize":
            headers = {"Mcp-Session-Id": self.session_id} if self.session_id else {}
            return httpx.Response(
                200, headers=headers, json={"jsonrpc": "2.0", "id": body["id"], "result": {"protocolVersion": "2025-06-18"}}
            )
        if self.session_id and request.headers.get("mcp-session-id") != self.session_id:
            return httpx.Response(400, json={"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "missing session"}})
        if "id" not in body:
            return httpx.Response(202)
        if method == "tools/list":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {"tools": [{"name": "read"}, {"name": "echo"}]}})
        if method == "tools/call" and self.call_answer is not None:
            return self.call_answer(body)
        result = {"jsonrpc": "2.0", "id": body["id"], "result": {"content": [{"type": "text", "text": f"ok:{method}"}]}}
        return httpx.Response(200, json=result)

    def posts(self) -> list[dict]:
        return [json.loads(r.content) for r in self.requests if r.method == "POST"]


def _drive(monkeypatch, server: FixtureServer, lines: list[Any], **kwargs: Any) -> list[dict]:
    monkeypatch.setattr("httpx.AsyncClient", lambda **kw: _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(server), **kw))
    encoded = [(line if isinstance(line, str) else json.dumps(line)).encode() + b"\n" for line in lines]
    monkeypatch.setattr(proxy, "create_async_stdin_reader", AsyncMock(return_value=object()))
    monkeypatch.setattr(proxy, "read_async_stdin_line", AsyncMock(side_effect=[*encoded, b""]))
    stdout = SimpleNamespace(buffer=io.BytesIO())
    monkeypatch.setattr(proxy.sys, "stdout", stdout)
    assert asyncio.run(proxy._proxy_sse_server(BASE, **kwargs)) == 0
    return [json.loads(line) for line in stdout.buffer.getvalue().decode().splitlines()]


_HANDSHAKE = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
]


def test_json_response_uses_single_endpoint_and_round_trips_session(monkeypatch):
    server = FixtureServer()
    written = _drive(monkeypatch, server, [*_HANDSHAKE, _call(2, "read", {"path": "/tmp/a"})], block_undeclared=True)

    assert [item["id"] for item in written] == [1, 2]
    assert written[1]["result"]["content"][0]["text"] == "ok:tools/call"
    posts = [r for r in server.requests if r.method == "POST"]
    assert {str(r.url) for r in posts} == {BASE}
    assert [b.get("method") for b in server.posts()] == ["initialize", "notifications/initialized", "tools/list", "tools/call"]
    assert "mcp-session-id" not in posts[0].headers
    assert all(r.headers["mcp-session-id"] == SESSION for r in posts[1:])
    assert all("text/event-stream" in r.headers["accept"] for r in posts)
    assert posts[-1].headers["mcp-method"] == "tools/call"
    assert posts[-1].headers["mcp-name"] == "read"
    deletes = [r for r in server.requests if r.method == "DELETE"]
    assert len(deletes) == 1 and deletes[0].headers["mcp-session-id"] == SESSION


def test_sse_response_returns_correlated_result_and_skips_notifications(monkeypatch):
    def answer(body: dict) -> httpx.Response:
        progress = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}}
        final = {"jsonrpc": "2.0", "id": body["id"], "result": {"content": [{"type": "text", "text": "streamed"}]}}
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, text=_sse(progress, final))

    written = _drive(monkeypatch, FixtureServer(call_answer=answer), [*_HANDSHAKE, _call(2, "echo")])
    assert written[-1] == {"jsonrpc": "2.0", "id": 2, "result": {"content": [{"type": "text", "text": "streamed"}]}}


def test_tool_responses_are_still_scanned_for_credentials(monkeypatch, tmp_path):
    secret_text = "token AKIA" + "Z" * 16

    def answer(body: dict) -> httpx.Response:
        final = {"jsonrpc": "2.0", "id": body["id"], "result": {"content": [{"type": "text", "text": secret_text}]}}
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, text=_sse(final))

    log_path = tmp_path / "audit.jsonl"
    _drive(monkeypatch, FixtureServer(call_answer=answer), [*_HANDSHAKE, _call(2, "read")], log_path=str(log_path))
    detectors = {json.loads(line).get("detector") for line in log_path.read_text().splitlines()}
    assert "credential_leak" in detectors
    assert secret_text not in log_path.read_text()


@pytest.mark.parametrize("bad", ["has space", "x" * (mcp_protocol.MAX_SESSION_ID_LENGTH + 1), "tab\tid"])
def test_invalid_server_session_id_fails_closed(monkeypatch, bad):
    server = FixtureServer(session_id=bad)
    written = _drive(monkeypatch, server, [_HANDSHAKE[0], _call(2, "read")])
    assert written[0]["id"] == 1 and "error" in written[0]
    assert "session" in written[0]["error"]["message"].lower()
    assert all("mcp-session-id" not in r.headers for r in server.requests)


def test_session_id_only_taken_from_initialize(monkeypatch):
    def answer(body: dict) -> httpx.Response:
        return httpx.Response(
            200, headers={"Mcp-Session-Id": "attacker-chosen"}, json={"jsonrpc": "2.0", "id": body["id"], "result": {"content": []}}
        )

    server = FixtureServer(call_answer=answer)
    _drive(monkeypatch, server, [*_HANDSHAKE, _call(2, "read"), _call(3, "echo")])
    posts = [r for r in server.requests if r.method == "POST"]
    assert {r.headers.get("mcp-session-id") for r in posts[1:]} == {SESSION}


def test_client_supplied_session_metadata_is_not_forwarded_as_header(monkeypatch):
    server = FixtureServer(session_id=None)
    injected = _call(2, "read")
    injected["params"]["_meta"] = {"Mcp-Session-Id": "other-tenant-session"}
    _drive(monkeypatch, server, [*_HANDSHAKE, injected])
    assert all("mcp-session-id" not in r.headers for r in server.requests)
    assert not [r for r in server.requests if r.method == "DELETE"]


def test_expired_session_is_dropped_and_reported(monkeypatch):
    def answer(body: dict) -> httpx.Response:
        return httpx.Response(404)

    server = FixtureServer(call_answer=answer)
    written = _drive(monkeypatch, server, [*_HANDSHAKE, _call(2, "read"), _call(3, "echo")])
    assert "re-initialize" in written[1]["error"]["message"]
    last = [r for r in server.requests if r.method == "POST"][-1]
    assert "mcp-session-id" not in last.headers
    assert not [r for r in server.requests if r.method == "DELETE"]


def _rejected(monkeypatch, answer: Callable[[dict], httpx.Response]) -> dict:
    written = _drive(monkeypatch, FixtureServer(call_answer=answer), [*_HANDSHAKE, _call(2, "read")])
    assert written[-1]["id"] == 2
    return written[-1]["error"]


def test_oversize_sse_event_is_rejected(monkeypatch):
    monkeypatch.setattr(proxy_upstream, "MAX_PROXY_SSE_EVENT_BYTES", 256)

    def answer(body: dict) -> httpx.Response:
        final = {"jsonrpc": "2.0", "id": body["id"], "result": {"content": [{"type": "text", "text": "x" * 1024}]}}
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, text=_sse(final))

    error = _rejected(monkeypatch, answer)
    assert error["code"] == -32603 and "event exceeds size limit" in error["message"]
    assert "xxxx" not in error["message"]


def test_oversize_total_sse_response_is_rejected(monkeypatch):
    monkeypatch.setattr(proxy_upstream, "MAX_PROXY_RESPONSE_BYTES", 2048)

    def answer(body: dict) -> httpx.Response:
        noise = [{"jsonrpc": "2.0", "method": "notifications/message", "params": {"data": "y" * 200}}] * 20
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, text=_sse(*noise))

    assert "response exceeds size limit" in _rejected(monkeypatch, answer)["message"]


def test_unbounded_event_count_is_rejected(monkeypatch):
    monkeypatch.setattr(proxy_upstream, "MAX_PROXY_SSE_EVENTS", 5)

    def answer(body: dict) -> httpx.Response:
        noise = [{"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}] * 10
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, text=_sse(*noise))

    assert "too many events" in _rejected(monkeypatch, answer)["message"]


def test_stream_that_never_answers_hits_the_deadline(monkeypatch):
    monkeypatch.setattr(proxy_upstream, "PROXY_RESPONSE_DEADLINE_SECONDS", 0.2)

    class Trickle(httpx.AsyncByteStream):
        async def __aiter__(self):
            while True:
                await asyncio.sleep(0.05)
                yield b": keepalive\n\n"

    def answer(body: dict) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=Trickle())

    assert "deadline" in _rejected(monkeypatch, answer)["message"]


def test_non_mcp_content_type_is_rejected(monkeypatch):
    def answer(body: dict) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<html>login</html>")

    error = _rejected(monkeypatch, answer)
    assert "content type" in error["message"] and "login" not in error["message"]


def test_upstream_status_error_is_reported(monkeypatch):
    error = _rejected(monkeypatch, lambda body: httpx.Response(502))
    assert error == {"code": -32603, "message": "Upstream server error: 502"}


def test_initialize_failure_returns_error_instead_of_hanging(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    monkeypatch.setattr("httpx.AsyncClient", lambda **kw: _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr(proxy, "create_async_stdin_reader", AsyncMock(return_value=object()))
    monkeypatch.setattr(proxy, "read_async_stdin_line", AsyncMock(side_effect=[json.dumps(_HANDSHAKE[0]).encode() + b"\n", b""]))
    stdout = SimpleNamespace(buffer=io.BytesIO())
    monkeypatch.setattr(proxy.sys, "stdout", stdout)
    assert asyncio.run(proxy._proxy_sse_server(BASE)) == 0
    written = [json.loads(line) for line in stdout.buffer.getvalue().decode().splitlines()]
    assert written == [{"jsonrpc": "2.0", "id": 1, "error": {"code": -32603, "message": "Upstream server error: 500"}}]


def test_compat_endpoints_flag_keeps_legacy_paths(monkeypatch):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        body = json.loads(request.content)
        if request.url.path.endswith("/tools/list"):
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {"tools": [{"name": "read"}]}})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body.get("id"), "result": {"content": []}})

    monkeypatch.setattr("httpx.AsyncClient", lambda **kw: _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler), **kw))
    lines = [json.dumps(m).encode() + b"\n" for m in (_HANDSHAKE[0], _call(2, "read"))]
    monkeypatch.setattr(proxy, "create_async_stdin_reader", AsyncMock(return_value=object()))
    monkeypatch.setattr(proxy, "read_async_stdin_line", AsyncMock(side_effect=[*lines, b""]))
    monkeypatch.setattr(proxy.sys, "stdout", SimpleNamespace(buffer=io.BytesIO()))
    assert asyncio.run(proxy._proxy_sse_server(BASE, compat_endpoints=True)) == 0
    assert seen == ["/mcp/tools/list", "/mcp/message", "/mcp/tools/call"]


def test_cli_defaults_to_streamable_and_flag_selects_compat(monkeypatch):
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    seen: list[bool] = []

    async def fake(**kwargs: Any) -> int:
        seen.append(kwargs["compat_endpoints"])
        return 0

    monkeypatch.setattr("agent_bom.proxy._proxy_sse_server", fake)
    assert runner.invoke(main, ["proxy", "--url", BASE]).exit_code == 0
    assert runner.invoke(main, ["proxy", "--url", BASE, "--compat-endpoints"]).exit_code == 0
    assert seen == [False, True]
    result = runner.invoke(main, ["proxy", "--no-isolate", "--compat-endpoints", "--", "echo"])
    assert result.exit_code == 2 and "--compat-endpoints" in result.output


def _sse_response(payload: bytes) -> Any:
    class Resp:
        async def aiter_bytes(self):
            yield payload

    return Resp()


def test_sse_messages_bounds_event_size_and_count():
    async def collect(payload: bytes, **kw: Any) -> list[dict]:
        return [event async for event, _ in mcp_protocol.sse_messages(_sse_response(payload), 1 << 20, **kw)]

    two = b'data: {"a": 1}\n\ndata: {"b": 2}\n\n'
    assert asyncio.run(collect(two)) == [{"a": 1}, {"b": 2}]
    with pytest.raises(ValueError, match="too many events"):
        asyncio.run(collect(two, max_events=1))
    with pytest.raises(ValueError, match="event exceeds size limit"):
        asyncio.run(collect(b"data: " + b"z" * 64 + b"\n\n", max_event_bytes=32))
    with pytest.raises(ValueError, match="event exceeds size limit"):
        asyncio.run(collect(b"data: " + b"z" * 64, max_event_bytes=32))


@pytest.mark.parametrize(
    ("value", "ok"),
    [(SESSION, True), ("a" * mcp_protocol.MAX_SESSION_ID_LENGTH, True), ("", False), ("a b", False), ("a\r\nX-Evil: 1", False)],
)
def test_validate_session_id(value, ok):
    if ok:
        assert mcp_protocol.validate_session_id(value) == value
    else:
        with pytest.raises(ValueError, match="session"):
            mcp_protocol.validate_session_id(value)


def test_failed_tool_discovery_never_logs_upstream_credentials(caplog):
    import asyncio
    import logging

    from agent_bom.proxy import _SseProxySession

    session = _SseProxySession(
        "https://user:hunter2pass@mcp.example.com/mcp?api_key=sk-live-abcdef1234567890",
        {},
        None,
        block_undeclared=False,
        alert_webhook=None,
    )

    class _Failing:
        async def tool_catalog(self, headers):
            raise RuntimeError("upstream unavailable")

    session.upstream = _Failing()
    with caplog.at_level(logging.WARNING, logger="agent_bom.proxy"):
        asyncio.run(session._discover_tools())
    logged = caplog.text
    assert "https://mcp.example.com/mcp" in logged
    for secret in ("hunter2pass", "sk-live-abcdef1234567890", "user:"):
        assert secret not in logged
