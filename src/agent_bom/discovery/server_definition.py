"""Read fields of a raw MCP server definition, and report one that failed validation."""

from __future__ import annotations

from agent_bom.models import MCPServer
from agent_bom.scanners.mcp_launch_risk import plaintext_env_secrets
from agent_bom.security import SecurityError, sanitize_env_vars


def string_field(value: object) -> str:
    return value if isinstance(value, str) else ""


def args_field(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def blocked_mcp_server(name: str, server_def: dict, config_path: str, error: SecurityError) -> MCPServer:
    """Keep a blocked server in the report, with its recipe readable.

    A blocked launcher is what the audit most needs to judge.
    """
    blocked_env = server_def.get("env", {})
    return MCPServer(
        name=name,
        command=string_field(server_def.get("command", "")),
        args=args_field(server_def.get("args", [])),
        env=sanitize_env_vars(blocked_env) if isinstance(blocked_env, dict) else {},
        config_path=config_path,
        security_blocked=True,
        security_warnings=[str(error)],
        plaintext_env_secrets=plaintext_env_secrets(blocked_env),
    )
