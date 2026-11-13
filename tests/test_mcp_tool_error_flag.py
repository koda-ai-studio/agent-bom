"""Every refused, rate-limited or invalid tool call is ``isError: true`` on the wire, in every auth mode."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from mcp import Client
from starlette.testclient import TestClient

from agent_bom.mcp_tools import public_tier

_ACCEPT = {"Accept": "application/json, text/event-stream", "mcp-protocol-version": "2025-11-25"}
_INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "error-flag", "version": "1"}},
}
_TOKEN = "full-access-error-flag-credential"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT", (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat())
    for name in (public_tier.PUBLIC_READONLY_ENV, public_tier.FORWARDED_HOP_COUNT_ENV, public_tier.PUBLIC_CALLER_RATE_LIMIT_ENV):
        monkeypatch.delenv(name, raising=False)
    public_tier.reset_public_rate_windows()
    yield
    public_tier.reset_public_rate_windows()


def _result(response) -> dict[str, Any]:
    for line in response.text.splitlines():
        if line.startswith("data: "):
            return json.loads(line[6:])["result"]
    return response.json()["result"]


def _call(client: TestClient, name: str, arguments: dict[str, Any], rid: int, headers: dict[str, str] | None = None) -> dict[str, Any]:
    body = {"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    return _result(client.post("/mcp", headers={**_ACCEPT, **(headers or {})}, json=body))


def test_the_31st_anonymous_call_is_rate_limited_and_flagged_as_an_error(monkeypatch):
    from agent_bom.mcp_server import create_mcp_server

    monkeypatch.setenv(public_tier.PUBLIC_READONLY_ENV, "1")
    server = create_mcp_server(host="0.0.0.0", port=8000, bearer_token=None, profile="public")
    stub = AsyncMock(return_value=json.dumps({"found": False}))
    with (
        patch("agent_bom.mcp_tools.intel.intel_lookup_impl", new=stub),
        TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client,
    ):
        assert client.post("/mcp", headers=_ACCEPT, json=_INIT).status_code == 200
        results = [_call(client, "intel_lookup", {"advisory_id": "CVE-2024-0001"}, rid) for rid in range(2, 33)]

    assert all(result["isError"] is False for result in results[:30])
    limited = results[30]
    assert json.loads(limited["content"][0]["text"])["rate_limited"] is True
    assert limited["isError"] is True


def test_an_anonymous_refused_ecosystem_is_flagged_as_an_error(monkeypatch):
    from agent_bom.mcp_server import create_mcp_server

    monkeypatch.setenv(public_tier.PUBLIC_READONLY_ENV, "1")
    server = create_mcp_server(host="0.0.0.0", port=8000, bearer_token=None, profile="public")
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        client.post("/mcp", headers=_ACCEPT, json=_INIT)
        result = _call(client, "check", {"package": "flask", "ecosystem": "not-an-ecosystem"}, 2)
    assert result["isError"] is True
    assert "not-an-ecosystem" in result["content"][0]["text"]


def test_a_bearer_callers_rate_limited_call_is_flagged_as_an_error(monkeypatch):
    from agent_bom import mcp_server

    monkeypatch.setattr(mcp_server, "_check_caller_rate_limit", lambda _caller: 7.0)
    server = mcp_server.create_mcp_server(host="127.0.0.1", port=8000, bearer_token=_TOKEN, profile="scan")
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        auth = {"Authorization": f"Bearer {_TOKEN}"}
        init = client.post("/mcp", headers={**_ACCEPT, **auth}, json=_INIT)
        session = {**auth, "mcp-session-id": init.headers["mcp-session-id"]}
        result = _call(client, "check", {"package": "flask@2.0.0", "ecosystem": "pypi"}, 2, session)
    assert json.loads(result["content"][0]["text"])["rate_limited"] is True
    assert result["isError"] is True


def test_in_process_rate_limited_and_error_payload_calls_are_flagged(monkeypatch):
    from agent_bom import mcp_server

    answers = [json.dumps({"error": "lookup failed"}), json.dumps({"found": False}), json.dumps({"found": False})]
    with patch("agent_bom.mcp_tools.intel.intel_lookup_impl", new=AsyncMock(side_effect=answers)):
        server = mcp_server.create_mcp_server(profile="scan")

        async def run() -> tuple[Any, Any, Any]:
            async with Client(server) as client:
                failed = await client.call_tool("intel_lookup", {"advisory_id": "CVE-2024-0001"})
                ok = await client.call_tool("intel_lookup", {"advisory_id": "CVE-2024-0001"})
                monkeypatch.setattr(mcp_server, "_check_caller_rate_limit", lambda _caller: 3.0)
                limited = await client.call_tool("intel_lookup", {"advisory_id": "CVE-2024-0001"})
            return failed, ok, limited

        failed, ok, limited = asyncio.run(run())
    assert failed.is_error is True
    assert ok.is_error is False
    assert limited.is_error is True
    assert json.loads(limited.content[0].text)["rate_limited"] is True
