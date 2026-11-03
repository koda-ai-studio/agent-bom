"""Declared auth headers count as authentication; non-auth headers do not.

Only header NAMES are recorded by discovery; values never reach the posture
evaluator, findings or logs.
"""

from __future__ import annotations

import pytest

from agent_bom.discovery.config_parsers import parse_mcp_config
from agent_bom.domain.mcp_auth_headers import auth_header_names
from agent_bom.mcp_auth_posture import evaluate_mcp_auth_posture
from agent_bom.models import Agent, AgentType, MCPServer

_PLACEHOLDER = "fixture-" + "header-value"


def _server(headers: dict[str, str]) -> MCPServer:
    return parse_mcp_config(
        {"mcpServers": {"remote": {"type": "http", "url": "https://mcp.example.com/mcp", "headers": headers}}}, "fixture"
    )[0]


def _unauthenticated(server: MCPServer) -> list:
    agent = Agent(name="a", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/a.json", mcp_servers=[server])
    findings = evaluate_mcp_auth_posture([agent])
    for finding in findings:
        assert _PLACEHOLDER not in repr(finding.evidence)
        assert _PLACEHOLDER not in (finding.description or "")
    return [f for f in findings if f.evidence.get("mcp_auth_weakness") == "unauthenticated_server"]


@pytest.mark.parametrize("name", ["Authorization", "authorization", "X-API-Key", "Api-Key", "Proxy-Authorization", "x-auth-token"])
def test_auth_header_is_declared_auth(name: str) -> None:
    server = _server({name: _PLACEHOLDER})
    assert server.auth_mode == "configured-http-auth"
    assert _unauthenticated(server) == []


@pytest.mark.parametrize("headers", [{}, {"Content-Type": _PLACEHOLDER}, {"Accept": _PLACEHOLDER, "User-Agent": _PLACEHOLDER}])
def test_non_auth_headers_still_flagged(headers: dict[str, str]) -> None:
    server = _server(headers)
    assert server.auth_mode == "network-no-auth-observed"
    assert len(_unauthenticated(server)) == 1


def test_codex_bearer_token_env_var_counts() -> None:
    server = parse_mcp_config(
        {"mcpServers": {"remote": {"url": "https://mcp.example.com/mcp", "bearer_token_env_var": "REMOTE_MCP_TOKEN"}}}, "fixture"
    )[0]
    assert _unauthenticated(server) == []


def test_auth_header_names_is_case_insensitive_and_filters() -> None:
    assert auth_header_names(["AUTHORIZATION", "Content-Type", "x-api-key", 7]) == ["AUTHORIZATION", "x-api-key"]
