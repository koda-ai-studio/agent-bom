"""The no-login public lookup edition: ``--public-readonly --profile public``.

A separate internet-facing deployment that registers only the anonymous lookup
tools, advertises no credential, and can serve a directory domain-verification
token. Other tools must not exist on it at all, not merely be refused.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from agent_bom.mcp_server import create_mcp_server
from agent_bom.mcp_tools import openai_challenge, public_tier
from agent_bom.mcp_tools.profiles import get_profile

ROOT = Path(__file__).resolve().parents[1]
_ACCEPT = {"Accept": "application/json, text/event-stream"}
_CHALLENGE_PATH = "/.well-known/openai-apps-challenge"
_TOKEN = "Zq3-verification_token.0123456789abcdef"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT", (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat())
    for name in (
        public_tier.PUBLIC_READONLY_ENV,
        public_tier.FORWARDED_HOP_COUNT_ENV,
        openai_challenge.OPENAI_APPS_CHALLENGE_ENV,
        "AGENT_BOM_MCP_BEARER_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    public_tier.reset_public_rate_windows()
    yield
    public_tier.reset_public_rate_windows()


def _edition(monkeypatch):
    monkeypatch.setenv(public_tier.PUBLIC_READONLY_ENV, "1")
    return create_mcp_server(host="0.0.0.0", port=8000, bearer_token=None, profile="public")


def _event(response):
    for line in response.text.splitlines():
        if line.startswith("data: "):
            return json.loads(line[6:])
    return response.json()


def _session(client):
    headers = dict(_ACCEPT)
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "edition", "version": "1"}},
    }
    response = client.post("/mcp", headers=headers, json=init)
    assert response.status_code == 200, response.text
    headers.update({"mcp-session-id": response.headers["mcp-session-id"], "mcp-protocol-version": "2025-11-25"})
    client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    return headers, _event(response)["result"]


def _rpc(client, headers, method, params, rid=2):
    return client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params})


# ── Tool set ───────────────────────────────────────────────────────────────


def test_public_profile_is_exactly_the_two_lookup_tools():
    spec = get_profile("public")
    assert spec.tools == frozenset({"check", "intel_lookup"})
    assert spec.tools <= public_tier.PUBLIC_TOOL_ALLOWLIST
    assert spec.prompts == frozenset() and spec.resources == frozenset()


def test_edition_registers_only_lookup_tools(monkeypatch):
    server = _edition(monkeypatch)
    assert {tool.name for tool in server._tool_manager.list_tools()} == {"check", "intel_lookup"}


def test_anonymous_caller_lists_two_tools_and_nothing_else(monkeypatch):
    with TestClient(_edition(monkeypatch).streamable_http_app(), base_url="http://localhost:8000") as client:
        headers, init = _session(client)
        assert "profiles://catalog" not in init.get("instructions", "")
        tools = _event(_rpc(client, headers, "tools/list", {}))["result"]["tools"]
        assert {tool["name"] for tool in tools} == {"check", "intel_lookup"}
        for tool in tools:
            annotations = tool["annotations"]
            for hint in ("readOnlyHint", "destructiveHint", "openWorldHint"):
                assert isinstance(annotations.get(hint), bool), (tool["name"], hint)
            assert annotations["readOnlyHint"] is True and annotations["destructiveHint"] is False
        assert _event(_rpc(client, headers, "resources/list", {}, rid=3))["result"]["resources"] == []
        assert _event(_rpc(client, headers, "prompts/list", {}, rid=4))["result"]["prompts"] == []


@pytest.mark.parametrize("tool", ["scan", "generate_sbom", "registry_lookup", "agent_activity", "skill_scan", "nonexistent"])
def test_every_other_tool_is_refused(monkeypatch, tool):
    with TestClient(_edition(monkeypatch).streamable_http_app(), base_url="http://localhost:8000") as client:
        headers, _ = _session(client)
        response = _rpc(client, headers, "tools/call", {"name": tool, "arguments": {}})
        if response.status_code == 200:
            assert "error" in _event(response) or _event(response)["result"].get("isError") is True
        else:
            assert response.status_code == 401


def test_host_os_ecosystems_are_refused_and_described(monkeypatch):
    server = _edition(monkeypatch)
    check = next(tool for tool in server._tool_manager.list_tools() if tool.name == "check")
    ecosystem_text = check.parameters["properties"]["ecosystem"]["description"]
    assert "refuses" in ecosystem_text and "public" in ecosystem_text
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        headers, _ = _session(client)
        payload = _event(
            _rpc(client, headers, "tools/call", {"name": "check", "arguments": {"package": "openssl@3.0.0", "ecosystem": "deb"}})
        )
        assert "error" in payload and "public tier" in payload["error"]["message"]
        assert "authentication" not in payload["error"]["message"]


def test_intel_lookup_description_states_scope_and_limits(monkeypatch):
    server = _edition(monkeypatch)
    lookup = next(tool for tool in server._tool_manager.list_tools() if tool.name == "intel_lookup")
    description = lookup.description.lower()
    assert len(description) >= 150
    for phrase in ("cve", "ghsa", "bundled", "not found"):
        assert phrase in description, phrase


def test_edition_refuses_oauth(monkeypatch):
    monkeypatch.setenv(public_tier.PUBLIC_READONLY_ENV, "1")
    with pytest.raises(ValueError, match="public read-only"):
        create_mcp_server(host="0.0.0.0", port=8000, bearer_token=None, profile="public", oauth_enabled=True)


# ── Honest metadata ────────────────────────────────────────────────────────


def test_server_card_advertises_no_credential_and_only_lookups(monkeypatch):
    with TestClient(_edition(monkeypatch).streamable_http_app(), base_url="http://localhost:8000") as client:
        card = client.get("/.well-known/mcp/server-card.json").json()
        assert card["authentication"] == {
            "required": False,
            "schemes": [],
            "public_readonly": True,
            "anonymous_tools": ["check", "intel_lookup"],
        }
        assert [tool["name"] for tool in card["tools"]] == ["check", "intel_lookup"]
        assert card["prompts"] == [] and card["resources"] == []
        assert card["capabilities"]["read_only"] is True
        health = client.get("/health").json()
        assert health["auth_required"] is False and health["tool_count"] == 2
        assert client.get("/").json()["auth_required"] is False
        assert client.get("/.well-known/oauth-protected-resource").status_code == 404
        assert client.get("/.well-known/oauth-authorization-server").status_code == 404


def test_scan_profile_public_tier_still_reports_credential_required(monkeypatch):
    monkeypatch.setenv(public_tier.PUBLIC_READONLY_ENV, "1")
    server = create_mcp_server(host="127.0.0.1", port=8000, bearer_token="full-access-test-credential", profile="scan")
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        assert client.get("/.well-known/mcp/server-card.json").json()["authentication"]["required"] is True


# ── Domain verification challenge ──────────────────────────────────────────


def test_challenge_is_404_when_unset(monkeypatch):
    with TestClient(_edition(monkeypatch).streamable_http_app(), base_url="http://localhost:8000") as client:
        response = client.get(_CHALLENGE_PATH)
        assert response.status_code == 404
        assert _TOKEN not in response.text


def test_challenge_serves_exact_token_as_plain_text(monkeypatch):
    monkeypatch.setenv(openai_challenge.OPENAI_APPS_CHALLENGE_ENV, f"  {_TOKEN}\n")
    with TestClient(_edition(monkeypatch).streamable_http_app(), base_url="http://localhost:8000") as client:
        first = client.get(_CHALLENGE_PATH)
        second = client.get(_CHALLENGE_PATH, headers={"X-Forwarded-For": "203.0.113.9"}, params={"x": "1"})
        for response in (first, second):
            assert response.status_code == 200
            assert response.content == _TOKEN.encode()
            assert response.headers["content-type"].startswith("text/plain")
            assert response.headers["cache-control"] == "no-store"
            assert response.headers["x-content-type-options"] == "nosniff"
        assert client.post(_CHALLENGE_PATH).status_code == 405
        assert client.get(_CHALLENGE_PATH + "/extra").status_code == 404


@pytest.mark.parametrize("value", ["has space", "line\nbreak", "x" * 513, "", "   ", "tab\tchar", "ünicode"])
def test_challenge_rejects_malformed_tokens(monkeypatch, value):
    monkeypatch.setenv(openai_challenge.OPENAI_APPS_CHALLENGE_ENV, value)
    assert openai_challenge.challenge_token() is None
    with TestClient(_edition(monkeypatch).streamable_http_app(), base_url="http://localhost:8000") as client:
        assert client.get(_CHALLENGE_PATH).status_code == 404


def test_challenge_route_needs_no_credential_on_a_bearer_server(monkeypatch):
    monkeypatch.setenv(openai_challenge.OPENAI_APPS_CHALLENGE_ENV, _TOKEN)
    server = create_mcp_server(host="127.0.0.1", port=8000, bearer_token="full-access-test-credential", profile="scan")
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        assert client.get(_CHALLENGE_PATH).text == _TOKEN


def test_malformed_challenge_is_logged_without_its_value(monkeypatch, caplog):
    secret_shape = "bad token with spaces"
    monkeypatch.setenv(openai_challenge.OPENAI_APPS_CHALLENGE_ENV, secret_shape)
    with caplog.at_level("WARNING"):
        _edition(monkeypatch)
    assert any(openai_challenge.OPENAI_APPS_CHALLENGE_ENV in record.getMessage() for record in caplog.records)
    assert all(secret_shape not in record.getMessage() for record in caplog.records)


# ── CLI and container ──────────────────────────────────────────────────────


def test_cli_accepts_public_profile(monkeypatch):
    from click.testing import CliRunner

    from agent_bom.cli._server import mcp_server_cmd

    captured: dict = {}

    def fake_create(**kwargs):
        captured.update(kwargs)
        server = create_mcp_server(**kwargs)
        monkeypatch.setattr(server, "run", lambda **_: captured.setdefault("ran", True))
        return server

    monkeypatch.setattr("agent_bom.mcp_server.create_mcp_server", fake_create)
    args = ["--transport", "streamable-http", "--host", "0.0.0.0", "--public-readonly", "--profile", "public"]
    result = CliRunner().invoke(mcp_server_cmd, args, env={}, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert captured["profile"] == "public" and captured["public_readonly"] is True and captured.get("ran")
    assert "8 prompts" not in result.output and "Workflows   none" in result.output


def test_public_edition_dockerfile_runs_only_the_public_command():
    text = (ROOT / "deploy/docker/Dockerfile.public-mcp").read_text(encoding="utf-8")
    command = next(line for line in text.splitlines() if line.startswith("CMD "))
    assert "--public-readonly" in command and "--profile public" in command
    assert "--transport streamable-http" in command and "--host 0.0.0.0" in command
    assert "--bearer-token" not in command and "--allow-insecure-no-auth" not in command
    env_names = {match.group(1) for match in re.finditer(r"^ENV ([A-Z0-9_]+)=", text, re.M)}
    assert not {"AGENT_BOM_MCP_BEARER_TOKEN", "AGENT_BOM_OPENAI_APPS_CHALLENGE"} & env_names
    assert "USER abom" in text and "HEALTHCHECK" in text and "/health" in text


def test_existing_oauth_service_config_is_untouched():
    railway = json.loads((ROOT / "railway.json").read_text(encoding="utf-8"))
    assert railway["build"]["dockerfilePath"] == "deploy/docker/Dockerfile.sse"
    sse = (ROOT / "deploy/docker/Dockerfile.sse").read_text(encoding="utf-8")
    assert "--public-readonly" not in next(line for line in sse.splitlines() if line.startswith("CMD "))
