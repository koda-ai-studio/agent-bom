"""A server variable set to nothing holds no credential, so it must not read as reachable."""

from __future__ import annotations

from agent_bom.context_graph import build_context_graph
from agent_bom.models import MCPServer


def test_blank_env_values_are_not_credentials() -> None:
    server = MCPServer(name="s", env={"GITHUB_TOKEN": "", "GH_TOKEN": "   ", "NVD_API_KEY": "real-looking"})
    assert server.env_credential_names == ["NVD_API_KEY"]
    assert server.credential_names == ["NVD_API_KEY"]


def test_a_reference_to_a_token_still_counts() -> None:
    server = MCPServer(name="s", env={"GITHUB_TOKEN": "${GITHUB_TOKEN}"})
    assert server.env_credential_names == ["GITHUB_TOKEN"]


def test_a_redacted_value_still_counts() -> None:
    server = MCPServer(name="s", env={"GITHUB_TOKEN": "***REDACTED***"})
    assert server.env_credential_names == ["GITHUB_TOKEN"]


def _credential_labels(env: dict[str, str]) -> list[str]:
    agents = [{"name": "a", "mcp_servers": [{"name": "s", "command": "uv", "env": env}]}]
    graph = build_context_graph(agents, [])
    return sorted(node.label for node in graph.nodes.values() if str(node.kind).lower().endswith("credential"))


def test_serialized_report_blank_env_makes_no_credential_node() -> None:
    assert _credential_labels({"GITHUB_TOKEN": ""}) == []
    assert _credential_labels({"GITHUB_TOKEN": "***REDACTED***"}) == ["GITHUB_TOKEN"]


def test_sanitizer_leaves_a_blank_value_blank_and_still_redacts_real_values() -> None:
    from agent_bom.security import sanitize_env_vars

    cleaned = sanitize_env_vars({"GITHUB_TOKEN": "", "GH_TOKEN": "   ", "NVD_API_KEY": "abc123"})
    assert cleaned["GITHUB_TOKEN"] == ""
    assert cleaned["GH_TOKEN"] == ""
    assert cleaned["NVD_API_KEY"] == "***REDACTED***"


def test_a_discovered_blanked_server_reports_no_credential() -> None:
    from agent_bom.security import sanitize_env_vars

    server = MCPServer(name="s", env=sanitize_env_vars({"GITHUB_TOKEN": "", "NVD_API_KEY": "abc123"}))
    assert server.env_credential_names == ["NVD_API_KEY"]
