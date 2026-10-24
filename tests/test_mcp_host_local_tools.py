"""Host-local MCP tools are refused over shared HTTP/SSE transports by default.

``agent_activity`` (this machine's coding-agent session history),
``browser_extension_scan`` (this machine's browser extensions) and host
auto-discovery in ``inventory`` / ``tool_risk_assessment`` disclose the server
operator's own workstation. That is the point over stdio, where the caller is
the operator. Over streamable HTTP or SSE any authenticated caller would read
it, so those calls are refused unless ``AGENT_BOM_MCP_ALLOW_HOST_LOCAL_TOOLS``
is set.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

pytest.importorskip("mcp")

from mcp import Client  # noqa: E402

from agent_bom.mcp_errors import CODE_AUTH_FORBIDDEN  # noqa: E402
from agent_bom.mcp_tools.host_local import HOST_LOCAL_OPT_IN_ENV  # noqa: E402

_TOKEN = "host-local-test-read-credential"
_FAKE_REPORT = {"schema_version": "agent_activity.v1", "sessions": [{"id": "s1"}], "summary": {}}


def _stdio_call(tool: str, args: dict[str, Any]) -> tuple[bool, str]:
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server(profile="full")

    async def _run():
        async with Client(server) as client:
            return await client.call_tool(tool, args)

    result = asyncio.run(_run())
    return bool(result.is_error), result.content[0].text  # type: ignore[union-attr]


def _http_call(tool: str, args: dict[str, Any]) -> tuple[bool, str]:
    from starlette.testclient import TestClient

    from agent_bom.mcp_server import create_mcp_server
    from tests.test_mcp_private_auth import _event

    server = create_mcp_server(host="127.0.0.1", port=8000, bearer_token=_TOKEN, profile="full")
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        headers = {"Accept": "application/json, text/event-stream", "Authorization": "Bearer " + _TOKEN}
        init = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
            },
        )
        assert init.status_code == 200
        headers.update({"mcp-session-id": init.headers["mcp-session-id"], "mcp-protocol-version": "2025-11-25"})
        client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
        response = client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": args}},
        )
        result = _event(response)["result"]
    return bool(result.get("isError")), result["content"][0]["text"]


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT", (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat())
    monkeypatch.delenv(HOST_LOCAL_OPT_IN_ENV, raising=False)
    monkeypatch.delenv("AGENT_BOM_MCP_REMOTE_BIND", raising=False)
    with (
        patch("agent_bom.mcp_tools.activity.build_activity_report", return_value=dict(_FAKE_REPORT)),
        patch("agent_bom.parsers.browser_extensions.discover_browser_extensions", return_value=[]),
        patch("agent_bom.discovery.discover_all", return_value=[]),
    ):
        yield home


_HOST_LOCAL_CALLS = [
    ("agent_activity", {}),
    ("browser_extension_scan", {}),
    ("inventory", {}),
    ("tool_risk_assessment", {"live": False}),
]


@pytest.mark.parametrize(("tool", "args"), _HOST_LOCAL_CALLS, ids=[c[0] for c in _HOST_LOCAL_CALLS])
def test_host_local_tool_refused_over_http(tool: str, args: dict[str, Any]) -> None:
    is_error, text = _http_call(tool, args)
    assert is_error, text
    assert CODE_AUTH_FORBIDDEN in text
    assert tool in text
    assert "reads the server host's local data" in text
    assert f"{HOST_LOCAL_OPT_IN_ENV}=1" in text
    assert "sessions" not in text


@pytest.mark.parametrize(("tool", "args"), _HOST_LOCAL_CALLS, ids=[c[0] for c in _HOST_LOCAL_CALLS])
def test_host_local_tool_allowed_over_stdio(tool: str, args: dict[str, Any]) -> None:
    is_error, text = _stdio_call(tool, args)
    assert not is_error, text
    assert CODE_AUTH_FORBIDDEN not in text


def test_opt_in_allows_agent_activity_over_http(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(HOST_LOCAL_OPT_IN_ENV, "1")
    is_error, text = _http_call("agent_activity", {})
    assert not is_error, text
    assert json.loads(text)["sessions"] == [{"id": "s1"}]


def test_remote_bind_refuses_even_without_request_object(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_MCP_REMOTE_BIND", "1")
    is_error, text = _stdio_call("agent_activity", {})
    assert is_error, text
    assert CODE_AUTH_FORBIDDEN in text


def test_inventory_with_workspace_config_path_is_allowed_over_http(_isolated: Path) -> None:
    project = _isolated / "proj"
    project.mkdir()
    is_error, text = _http_call("inventory", {"config_path": str(project)})
    assert not is_error, text
    assert json.loads(text)["total_agents"] == 0


def test_inventory_config_path_outside_sandbox_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    is_error, text = _stdio_call("inventory", {"config_path": str(outside)})
    assert is_error, text
    assert "AGENTBOM_MCP_VALIDATION_INVALID_PATH" in text
    assert "(argument: config_path)" in text


# Tools whose no-path default discovers this host's agent configs.
_HOST_DISCOVERY_CALLS = [
    ("scan", {}),
    ("where", {}),
    ("blast_radius", {"cve_id": "CVE-2024-3094"}),
    ("policy_check", {"policy_json": json.dumps({"name": "p", "rules": []})}),
    ("compliance", {"source": "local_scan"}),
    ("runtime_correlate", {}),
    ("context_graph", {"live": True}),
]


@pytest.mark.parametrize(("tool", "args"), _HOST_DISCOVERY_CALLS, ids=[c[0] for c in _HOST_DISCOVERY_CALLS])
def test_host_discovery_refused_over_http_without_a_path(tool: str, args: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    # With persisted findings, blast_radius answers from them and never reads
    # the host. This test is about the no-store path, so a store left by an
    # earlier test on the same worker must not answer first.
    monkeypatch.setattr("agent_bom.mcp_server._persisted_finding_evidence", lambda **_kwargs: {"available": False})
    is_error, text = _http_call(tool, args)
    assert is_error, text
    assert CODE_AUTH_FORBIDDEN in text
    assert "reads the server host's local data" in text
    assert f"{HOST_LOCAL_OPT_IN_ENV}=1" in text


@pytest.mark.parametrize(("tool", "args"), _HOST_DISCOVERY_CALLS, ids=[c[0] for c in _HOST_DISCOVERY_CALLS])
def test_host_discovery_allowed_over_stdio(tool: str, args: dict[str, Any]) -> None:
    _is_error, text = _stdio_call(tool, args)
    assert CODE_AUTH_FORBIDDEN not in text


def test_opt_in_allows_where_over_http(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(HOST_LOCAL_OPT_IN_ENV, "1")
    is_error, text = _http_call("where", {})
    assert not is_error, text
    assert "clients" in json.loads(text)


def test_scan_with_workspace_config_path_is_allowed_over_http(_isolated: Path) -> None:
    project = _isolated / "proj"
    project.mkdir()
    _is_error, text = _http_call("scan", {"config_path": str(project)})
    assert CODE_AUTH_FORBIDDEN not in text


def test_explicit_target_over_http_skips_host_discovery_and_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.mcp_tools import host_local

    monkeypatch.setattr(host_local, "shared_transport", lambda: True)
    warnings: list[str] = []
    assert host_local.host_discovery_allowed(explicit_target=True, warnings=warnings) is False
    assert warnings == [host_local.HOST_DISCOVERY_SKIPPED_WARNING]
    with pytest.raises(Exception, match=CODE_AUTH_FORBIDDEN):
        host_local.host_discovery_allowed(explicit_target=False, warnings=[])
    monkeypatch.setenv(HOST_LOCAL_OPT_IN_ENV, "1")
    assert host_local.host_discovery_allowed(explicit_target=False, warnings=warnings) is True
    monkeypatch.setattr(host_local, "shared_transport", lambda: False)
    monkeypatch.delenv(HOST_LOCAL_OPT_IN_ENV)
    assert host_local.host_discovery_allowed(explicit_target=False, warnings=warnings) is True
