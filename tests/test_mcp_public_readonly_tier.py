"""Opt-in anonymous read-only tier for the remote MCP server.

Anonymous callers reach only an allowlist of pure-lookup tools; every other
tool, resource and prompt still requires the configured bearer token.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from starlette.testclient import TestClient

from agent_bom.mcp_server import create_mcp_server
from agent_bom.mcp_tools import public_tier
from agent_bom.mcp_tools.tool_capabilities import _TOOL_CAPABILITY_CLASSES

_ACCEPT = {"Accept": "application/json, text/event-stream"}
_TOKEN = "full-access-test-credential"


@pytest.fixture(autouse=True)
def _isolated_state(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT", (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat())
    monkeypatch.delenv(public_tier.PUBLIC_READONLY_ENV, raising=False)
    monkeypatch.delenv(public_tier.FORWARDED_HOP_COUNT_ENV, raising=False)
    public_tier.reset_public_rate_windows()
    yield
    public_tier.reset_public_rate_windows()


def _event(response):
    for line in response.text.splitlines():
        if line.startswith("data: "):
            return json.loads(line[6:])
    return response.json()


def _session(client, token=None, extra_headers=None):
    headers = dict(_ACCEPT)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    headers.update(extra_headers or {})
    response = client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "public-tier", "version": "1"}},
        },
    )
    if response.status_code != 200:
        return response.status_code, None
    headers.update({"mcp-session-id": response.headers["mcp-session-id"], "mcp-protocol-version": "2025-11-25"})
    client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    return 200, headers


def _rpc(client, headers, method, params=None, rid=2):
    body = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        body["params"] = params
    return client.post("/mcp", headers=headers, json=body)


def _public_server(monkeypatch, *, bearer_token=_TOKEN, profile="scan"):
    monkeypatch.setenv(public_tier.PUBLIC_READONLY_ENV, "1")
    return create_mcp_server(host="127.0.0.1", port=8000, bearer_token=bearer_token, profile=profile)


def _stub_check():
    return patch("agent_bom.mcp_tools.scanning.check_impl", new=AsyncMock(return_value=json.dumps({"verdict": "clean"})))


# ── Default off ────────────────────────────────────────────────────────────


def test_public_tier_is_off_by_default(monkeypatch):
    assert public_tier.public_readonly_enabled() is False
    server = create_mcp_server(host="127.0.0.1", port=8000, bearer_token=_TOKEN, profile="scan")
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        assert _session(client)[0] == 401
        card = client.get("/.well-known/mcp/server-card.json").json()
        assert card["authentication"]["required"] is True
        assert card["authentication"]["public_readonly"] is False
        assert card["authentication"]["anonymous_tools"] == []
        health = client.get("/health").json()
        assert health["public_readonly"] is False


@pytest.mark.parametrize("value", ["0", "false", "", "no"])
def test_falsey_env_values_keep_tier_off(monkeypatch, value):
    monkeypatch.setenv(public_tier.PUBLIC_READONLY_ENV, value)
    assert public_tier.public_readonly_enabled() is False


# ── Anonymous access is the allowlist only ─────────────────────────────────


def test_anonymous_lists_only_allowlisted_tools(monkeypatch):
    server = _public_server(monkeypatch)
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        status, headers = _session(client)
        assert status == 200
        tools = {tool["name"] for tool in _event(_rpc(client, headers, "tools/list", {}))["result"]["tools"]}
        assert tools == {"check", "intel_lookup"}
        assert tools <= public_tier.PUBLIC_TOOL_ALLOWLIST
        assert _event(_rpc(client, headers, "resources/list", {}, rid=3))["result"]["resources"] == []
        assert _event(_rpc(client, headers, "prompts/list", {}, rid=4))["result"]["prompts"] == []


def test_anonymous_allowlisted_call_reaches_the_tool(monkeypatch):
    with _stub_check() as stub:
        server = _public_server(monkeypatch)
        with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
            _, headers = _session(client)
            response = _rpc(client, headers, "tools/call", {"name": "check", "arguments": {"package": "flask@2.0.0", "ecosystem": "pypi"}})
            assert response.status_code == 200
            assert "clean" in response.text
            assert stub.await_count == 1


@pytest.mark.parametrize("tool", ["scan", "compliance", "remediate", "generate_sbom", "policy_check", "exposure_paths", "nonexistent"])
def test_anonymous_non_allowlisted_tool_is_401(monkeypatch, tool):
    server = _public_server(monkeypatch)
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        _, headers = _session(client)
        response = _rpc(client, headers, "tools/call", {"name": tool, "arguments": {}})
        assert response.status_code == 401
        assert response.headers["www-authenticate"].lower().startswith("bearer")
        assert "Authentication required" in response.text


def test_anonymous_batch_with_non_allowlisted_call_is_401(monkeypatch):
    server = _public_server(monkeypatch)
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        _, headers = _session(client)
        batch = [
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "check", "arguments": {"package": "a@1"}}},
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "scan", "arguments": {}}},
        ]
        assert client.post("/mcp", headers=headers, json=batch).status_code == 401


@pytest.mark.parametrize(
    ("method", "params"),
    [
        ("resources/read", {"uri": "metrics://tools"}),
        ("prompts/get", {"name": "quick-audit"}),
        ("resources/templates/list", {}),
        ("completion/complete", {"ref": {"type": "ref/prompt", "name": "quick-audit"}, "argument": {"name": "x", "value": "y"}}),
    ],
)
def test_anonymous_non_tool_methods_are_refused(monkeypatch, method, params):
    server = _public_server(monkeypatch)
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        _, headers = _session(client)
        payload = _event(_rpc(client, headers, method, params))
        assert "error" in payload
        assert "authentication" in payload["error"]["message"].lower()


# ── Bearer path unchanged ──────────────────────────────────────────────────


def test_bearer_token_keeps_full_catalog_in_public_mode(monkeypatch):
    server = _public_server(monkeypatch)
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        status, headers = _session(client, _TOKEN)
        assert status == 200
        tools = {tool["name"] for tool in _event(_rpc(client, headers, "tools/list", {}))["result"]["tools"]}
        assert {"scan", "check", "compliance", "remediate"} <= tools
        assert len(tools) == 8


def test_invalid_bearer_token_is_not_downgraded_to_anonymous(monkeypatch):
    server = _public_server(monkeypatch)
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        assert _session(client, "wrong-credential")[0] == 401


def test_public_tier_without_bearer_token_still_refuses_other_tools(monkeypatch):
    server = _public_server(monkeypatch, bearer_token=None)
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        _, headers = _session(client)
        assert _rpc(client, headers, "tools/call", {"name": "scan", "arguments": {}}).status_code == 401
        assert _session(client, "anything")[0] == 401


def test_public_tier_rejects_oauth_combination(monkeypatch):
    monkeypatch.setenv(public_tier.PUBLIC_READONLY_ENV, "1")
    with pytest.raises(ValueError, match="public read-only"):
        create_mcp_server(host="127.0.0.1", port=8000, bearer_token=None, profile="scan", oauth_enabled=True)


# ── Input bounds and host-state refusals ───────────────────────────────────


def test_anonymous_oversized_body_is_413(monkeypatch):
    server = _public_server(monkeypatch)
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        _, headers = _session(client)
        padding = "x" * (public_tier.PUBLIC_MAX_BODY_BYTES + 1)
        response = _rpc(client, headers, "tools/call", {"name": "check", "arguments": {"package": padding}})
        assert response.status_code == 413


def test_anonymous_overlong_argument_is_refused(monkeypatch):
    with _stub_check() as stub:
        server = _public_server(monkeypatch)
        with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
            _, headers = _session(client)
            long_name = "a" * (public_tier.PUBLIC_MAX_ARG_CHARS + 1)
            payload = _event(_rpc(client, headers, "tools/call", {"name": "check", "arguments": {"package": long_name}}))
            assert "error" in payload or payload["result"].get("isError")
            assert stub.await_count == 0


@pytest.mark.parametrize("ecosystem", ["deb", "apk", "rpm", "DEB"])
def test_anonymous_os_package_check_is_refused(monkeypatch, ecosystem):
    """OS-package checks read the server host's distro and package database."""
    with _stub_check() as stub:
        server = _public_server(monkeypatch)
        with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
            _, headers = _session(client)
            arguments = {"package": "openssl@3.0.2", "ecosystem": ecosystem}
            payload = _event(_rpc(client, headers, "tools/call", {"name": "check", "arguments": arguments}))
            assert stub.await_count == 0
            assert "host" in json.dumps(payload).lower()


def test_anonymous_intel_lookup_skips_operator_advisory_data(monkeypatch):
    operator_view = patch("agent_bom.mcp_tools.intel._operator_advisory_view", return_value={"marker": "operator-private"})
    lookup = patch("agent_bom.mcp_tools.intel.lookup_advisory", return_value={"found": False})
    with operator_view as view, lookup:
        server = _public_server(monkeypatch)
        with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
            _, headers = _session(client)
            response = _rpc(client, headers, "tools/call", {"name": "intel_lookup", "arguments": {"advisory_id": "CVE-2024-3094"}})
            assert response.status_code == 200
            assert "operator-private" not in response.text
            assert view.call_count == 0
            _, authed = _session(client, _TOKEN)
            response = _rpc(client, authed, "tools/call", {"name": "intel_lookup", "arguments": {"advisory_id": "CVE-2024-3094"}})
            assert "operator-private" in response.text


# ── Per-caller rate limit ──────────────────────────────────────────────────


def test_anonymous_rate_limit_is_per_caller_and_enforced(monkeypatch):
    monkeypatch.setenv(public_tier.PUBLIC_CALLER_RATE_LIMIT_ENV, "2")
    monkeypatch.setenv(public_tier.FORWARDED_HOP_COUNT_ENV, "1")
    with _stub_check():
        server = _public_server(monkeypatch)
        with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
            _, first = _session(client, extra_headers={"X-Forwarded-For": "198.51.100.7"})
            call = {"name": "check", "arguments": {"package": "flask@2.0.0", "ecosystem": "pypi"}}
            assert "rate_limited" not in _rpc(client, first, "tools/call", call, rid=10).text
            assert "rate_limited" not in _rpc(client, first, "tools/call", call, rid=11).text
            assert "rate_limited" in _rpc(client, first, "tools/call", call, rid=12).text
            _, second = _session(client, extra_headers={"X-Forwarded-For": "198.51.100.8"})
            assert "rate_limited" not in _rpc(client, second, "tools/call", call, rid=13).text


def test_spoofed_forwarded_prefix_does_not_reset_the_bucket(monkeypatch):
    monkeypatch.setenv(public_tier.PUBLIC_CALLER_RATE_LIMIT_ENV, "1")
    monkeypatch.setenv(public_tier.FORWARDED_HOP_COUNT_ENV, "1")
    with _stub_check():
        server = _public_server(monkeypatch)
        with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
            call = {"name": "check", "arguments": {"package": "flask@2.0.0", "ecosystem": "pypi"}}
            _, first = _session(client, extra_headers={"X-Forwarded-For": "203.0.113.1, 198.51.100.7"})
            assert "rate_limited" not in _rpc(client, first, "tools/call", call).text
            _, spoof = _session(client, extra_headers={"X-Forwarded-For": "203.0.113.99, 198.51.100.7"})
            assert "rate_limited" in _rpc(client, spoof, "tools/call", call).text


def test_aggregate_anonymous_budget_caps_rotating_callers(monkeypatch):
    monkeypatch.setenv(public_tier.PUBLIC_TOTAL_RATE_LIMIT_ENV, "2")
    monkeypatch.setenv(public_tier.FORWARDED_HOP_COUNT_ENV, "1")
    with _stub_check():
        server = _public_server(monkeypatch)
        with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
            call = {"name": "check", "arguments": {"package": "flask@2.0.0", "ecosystem": "pypi"}}
            texts = []
            for index in range(3):
                _, headers = _session(client, extra_headers={"X-Forwarded-For": f"198.51.100.{index + 20}"})
                texts.append(_rpc(client, headers, "tools/call", call).text)
            assert ["rate_limited" in text for text in texts] == [False, False, True]


# ── Honest metadata ────────────────────────────────────────────────────────


def test_health_and_server_card_report_public_mode(monkeypatch):
    server = _public_server(monkeypatch)
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        health = client.get("/health").json()
        assert health["public_readonly"] is True
        assert health["anonymous_tools"] == ["check", "intel_lookup"]
        card = client.get("/.well-known/mcp/server-card.json").json()
        assert card["authentication"]["required"] is True
        assert card["authentication"]["public_readonly"] is True
        assert card["authentication"]["anonymous_tools"] == ["check", "intel_lookup"]
        assert client.get("/").json()["public_readonly"] is True


# ── Allowlist invariants ───────────────────────────────────────────────────

_HOST_OR_EGRESS_CLASSES = {"LOCAL_FILE_READ", "PROCESS_EXECUTION", "WRITE", "INTEGRATION", "GRAPH", "INVENTORY", "AUDIT", "EXPORT"}
_HOST_OR_URL_ARG_HINTS = ("path", "url", "uri", "host", "endpoint", "image", "file", "dir", "config", "command", "registry", "tenant")


def test_allowlist_is_small_and_every_entry_is_justified():
    assert public_tier.PUBLIC_TOOL_ALLOWLIST == frozenset(public_tier.PUBLIC_TOOL_SPECS)
    assert len(public_tier.PUBLIC_TOOL_ALLOWLIST) <= 5
    for name, spec in public_tier.PUBLIC_TOOL_SPECS.items():
        assert spec.rationale.strip(), name
        assert not set(_TOOL_CAPABILITY_CLASSES.get(name, ["UNKNOWN"])) & _HOST_OR_EGRESS_CLASSES, name


def test_allowlisted_tool_schemas_take_no_host_or_url_arguments(monkeypatch):
    """Adding a path/URL/host argument to an allowlisted tool must fail here."""
    server = create_mcp_server(host="127.0.0.1", port=8000, profile="full")
    registered = {tool.name: tool for tool in server._tool_manager.list_tools()}
    for name, spec in public_tier.PUBLIC_TOOL_SPECS.items():
        assert name in registered, f"allowlisted tool {name} is not registered"
        properties = set(registered[name].parameters.get("properties", {}))
        assert properties == set(spec.arguments), f"{name} arguments changed: re-review it for the public tier"
        for argument in properties:
            assert not any(hint in argument.lower() for hint in _HOST_OR_URL_ARG_HINTS), (name, argument)


def test_new_tools_default_to_auth_required(monkeypatch):
    server = create_mcp_server(host="127.0.0.1", port=8000, profile="full")
    every_tool = {tool.name for tool in server._tool_manager.list_tools()}
    assert len(every_tool) > 50
    for name in every_tool - public_tier.PUBLIC_TOOL_ALLOWLIST:
        assert public_tier.anonymous_call_allowed(name) is False, name
    assert public_tier.anonymous_call_allowed("tool_added_later") is False


# ── CLI ────────────────────────────────────────────────────────────────────


def _invoke_server(monkeypatch, args, env=None):
    from click.testing import CliRunner

    from agent_bom.cli._server import mcp_server_cmd

    captured = {}

    def fake_create(**kwargs):
        captured.update(kwargs)
        server = create_mcp_server(**kwargs)
        monkeypatch.setattr(server, "run", lambda **_: captured.setdefault("ran", True))
        return server

    monkeypatch.setattr("agent_bom.mcp_server.create_mcp_server", fake_create)
    result = CliRunner().invoke(mcp_server_cmd, args, env=env or {}, catch_exceptions=False)
    return result, captured


def test_cli_public_readonly_serves_remote_without_bearer(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_MCP_BEARER_TOKEN", raising=False)
    result, captured = _invoke_server(monkeypatch, ["--transport", "streamable-http", "--host", "0.0.0.0", "--public-readonly"])
    assert result.exit_code == 0, result.output
    assert captured["public_readonly"] is True and captured.get("ran")
    assert "Public read-only tier" in result.output


def test_cli_remote_without_bearer_or_public_tier_still_refuses(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_MCP_BEARER_TOKEN", raising=False)
    result, captured = _invoke_server(monkeypatch, ["--transport", "streamable-http", "--host", "0.0.0.0"])
    assert result.exit_code != 0
    assert "Refusing" in result.output
    assert not captured.get("ran")


def test_cli_public_readonly_requires_streamable_http(monkeypatch):
    result, captured = _invoke_server(monkeypatch, ["--transport", "sse", "--host", "0.0.0.0", "--public-readonly"])
    assert result.exit_code != 0
    assert "streamable-http" in result.output
    assert not captured.get("ran")
