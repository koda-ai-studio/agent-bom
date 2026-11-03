"""Credentials embedded in MCP args, URLs and headers count by name, never by value."""

from __future__ import annotations

import asyncio
import json

import pytest

from agent_bom.domain.mcp_embedded_credentials import command_arg_credential_names, embedded_credential_names
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package, Severity, Vulnerability
from agent_bom.security import sanitize_command_args

# Assembled at runtime so no secret-shaped literal sits in the repository.
_SECRET = "-".join(["placeholder", "value", "do", "not", "use"])
_DSN = f"postgres://svc:{_SECRET}@db.internal:5432/app"


def _server(**kwargs) -> MCPServer:
    return MCPServer(name="db", command="npx", **kwargs)


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["--auth-token", _SECRET], ["--auth-token"]),
        ([f"--api-key={_SECRET}"], ["--api-key"]),
        ([f"API_TOKEN={_SECRET}"], ["API_TOKEN"]),
        (["server-postgres", _DSN], ["postgres-url-password"]),
        ([f"--dsn={_DSN}"], ["postgres-url-password"]),
        ([f"https://api.example.test/v1?api_key={_SECRET}&page=2"], ["https-url-param:api_key"]),
        (["--port", "8080", "https://example.test/path", "user@host"], []),
        (["--verbose", "--auth-token"], []),
    ],
)
def test_arg_names_follow_the_redaction_predicates(args, expected):
    assert command_arg_credential_names(args) == expected
    if expected:
        assert _SECRET not in " ".join(sanitize_command_args(args))


def test_every_redacted_arg_is_counted_and_nothing_else():
    args = ["-y", "--auth-token", _SECRET, "--dsn", _DSN, "--region", "us-east-1"]
    redacted = [i for i, (raw, safe) in enumerate(zip(args, sanitize_command_args(args), strict=True)) if raw != safe]
    assert redacted == [2, 4]
    assert command_arg_credential_names(args) == ["--auth-token", "postgres-url-password"]


def test_headers_and_server_url_are_counted_by_name():
    names = embedded_credential_names([], f"https://bot:{_SECRET}@mcp.example.test/sse", ["Authorization", "X-Request-Id", "X-Api-Key"])
    assert names == ["https-url-password", "header:Authorization", "header:X-Api-Key"]


def test_server_credential_names_include_embedded_after_env():
    server = _server(
        args=["@mcp/server-postgres", _DSN],
        env={"GITHUB_TOKEN": "x", "LOG_LEVEL": "debug"},
        connection_metadata={"header_names": ["Authorization"]},
    )
    assert server.env_credential_names == ["GITHUB_TOKEN"]
    assert server.embedded_credential_names == ["postgres-url-password", "header:Authorization"]
    assert server.credential_names == ["GITHUB_TOKEN", "postgres-url-password", "header:Authorization"]
    assert server.has_credentials


def test_embedded_names_do_not_change_server_identity_or_auth_mode():
    env_only = _server(args=["@mcp/server-postgres", _DSN], env={"GITHUB_TOKEN": "x"})
    baseline_mode = env_only.auth_mode
    fingerprint = env_only.fingerprint
    stable_id = env_only.stable_id
    assert env_only.embedded_credential_names
    env_only.connection_metadata = {}
    assert env_only.auth_mode == baseline_mode == "env-credentials"
    assert env_only.fingerprint == fingerprint
    assert env_only.stable_id == stable_id
    url_only = _server(url=f"https://bot:{_SECRET}@mcp.example.test/sse")
    assert url_only.auth_mode == "url-embedded-credentials"


def test_blast_radius_and_json_expose_the_name_but_never_the_value(monkeypatch):
    import agent_bom.scanners as scanners_mod
    from agent_bom.output import to_json
    from agent_bom.scanners.package_scan import scan_agents

    vuln = Vulnerability(id="CVE-2099-0001", summary="test advisory", severity=Severity.HIGH, cvss_score=8.1, cwe_ids=["CWE-94"])
    pkg = Package(name="pg-driver", version="1.0.0", ecosystem="npm")
    server = _server(args=["@mcp/server-postgres", _DSN, "--auth-token", _SECRET], packages=[pkg])
    agent = Agent(name="agent", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/a.json", mcp_servers=[server])

    async def fake_scan_packages(packages, **_kwargs):
        for package in packages:
            package.vulnerabilities = [vuln]
        return len(packages)

    monkeypatch.setattr(scanners_mod, "scan_packages", fake_scan_packages)
    monkeypatch.setattr(scanners_mod, "get_registry_entry", lambda _server: None, raising=False)
    radii = asyncio.run(scan_agents([agent], show_scan_banner=False))

    assert radii and set(radii[0].exposed_credentials) == {"postgres-url-password", "--auth-token"}
    assert set(radii[0].all_server_credentials) == {"postgres-url-password", "--auth-token"}
    doc = to_json(AIBOMReport(agents=[agent], blast_radii=radii))
    rendered = json.dumps(doc)
    assert _SECRET not in rendered
    server_doc = doc["agents"][0]["mcp_servers"][0]
    assert server_doc["credential_env_vars"] == []
    assert server_doc["embedded_credential_names"] == ["postgres-url-password", "--auth-token"]
    assert server_doc["has_credentials"] is True
    row = doc["blast_radius"][0]
    assert set(row["exposed_credentials"]) == {"postgres-url-password", "--auth-token"}
