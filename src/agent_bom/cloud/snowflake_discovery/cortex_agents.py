"""Cortex Agent inventory: SHOW AGENTS, DESCRIBE AGENT specifications and agent grants.

Every query is read-only. ``DESCRIBE AGENT`` returns the agent specification as
JSON in ``agent_spec`` (NULL for a secure agent unless the owner role is active);
its ``tools`` declare each tool's ``tool_spec`` and ``tool_resources`` maps a
tool name to the objects it runs against. Only those declared objects are
attributed to the agent.
"""

from __future__ import annotations

import json
from typing import Any

from agent_bom.canonical_ids import snowflake_cortex_agent_node_id, snowflake_fqn, snowflake_stored_fqn

from ..snowflake_common import _quote_sf_identifier
from ._base import _for_each_row, _warn_with

CORTEX_AGENT_SOURCE = "snowflake-cortex-agents"
MAX_CORTEX_AGENTS = 500
# Privileges that let a role run the agent. Cortex Agents take permissions from
# the request's Snowflake context, so these roles are the agent's execution context.
EXECUTION_PRIVILEGES = frozenset({"USAGE", "OWNERSHIP"})
_ROLE_GRANTEE_KINDS = frozenset({"ROLE", "ACCOUNT ROLE", "DATABASE ROLE", "DATABASE_ROLE"})


def _quoted_fqn(database: str, schema: str, name: str) -> str:
    return ".".join(_quote_sf_identifier(part) for part in (database, schema, name))


def _text(value: Any) -> str:
    return str(value).strip() if value not in (None, "") else ""


def _warehouse(resources: dict[str, Any]) -> str:
    env = resources.get("execution_environment")
    if isinstance(env, dict) and _text(env.get("type")).lower() in ("", "warehouse"):
        return snowflake_fqn(env.get("warehouse")) if _text(env.get("warehouse")) else ""
    return ""


def _stage_fqn(stage_path: str) -> str:
    if not stage_path.startswith("@"):
        return ""
    return snowflake_fqn(stage_path[1:].split("/", 1)[0])


def _tool_resources(tool_type: str, resources: dict[str, Any]) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []

    def add(kind: str, fqn: str) -> None:
        if fqn:
            found.append({"kind": kind, "fqn": fqn})

    if tool_type == "cortex_analyst_text_to_sql":
        add("semantic_view", snowflake_fqn(resources.get("semantic_view")) if _text(resources.get("semantic_view")) else "")
        add("stage", _stage_fqn(_text(resources.get("semantic_model_file"))))
    elif tool_type == "cortex_search":
        service = _text(resources.get("search_service")) or _text(resources.get("name"))
        add("cortex_search_service", snowflake_fqn(service) if service else "")
    elif tool_type == "generic":
        kind = "procedure" if _text(resources.get("type")).lower() == "procedure" else "function"
        add(kind, snowflake_fqn(resources.get("identifier")) if _text(resources.get("identifier")) else "")
    add("warehouse", _warehouse(resources))
    return found


def parse_agent_spec(spec: Any) -> list[dict[str, Any]] | None:
    """Declared tools from an agent specification, or ``None`` when it cannot be read."""
    if isinstance(spec, str):
        try:
            spec = json.loads(spec)
        except (json.JSONDecodeError, TypeError):
            return None
    if not isinstance(spec, dict):
        return None
    raw_resources = spec.get("tool_resources")
    resources_by_tool: dict[str, Any] = raw_resources if isinstance(raw_resources, dict) else {}
    tools: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in spec.get("tools") or []:
        tool_spec = entry.get("tool_spec") if isinstance(entry, dict) else None
        if not isinstance(tool_spec, dict):
            continue
        name = _text(tool_spec.get("name"))
        if not name or name in seen:
            continue
        seen.add(name)
        tool_type = _text(tool_spec.get("type"))
        tool_resources = resources_by_tool.get(name)
        resources: dict[str, Any] = tool_resources if isinstance(tool_resources, dict) else {}
        tools.append({"name": name, "type": tool_type, "resources": _tool_resources(tool_type, resources)})
    return tools


def _describe(conn: Any, database: str, schema: str, name: str, warnings: list[str]) -> dict[str, Any]:
    described: dict[str, Any] = {}
    _for_each_row(
        conn,
        f"DESCRIBE AGENT {_quoted_fqn(database, schema, name)}",  # nosec B608 — identifiers quoted
        lambda row: described.update(row) if not described else None,
        _warn_with(warnings, f"Could not describe Cortex Agent {database}.{schema}.{name}"),
    )
    return described


def _execution_roles(conn: Any, database: str, schema: str, name: str, warnings: list[str]) -> list[dict[str, str]]:
    roles: dict[tuple[str, str], dict[str, str]] = {}

    def handle(row: dict[str, Any]) -> None:
        privilege = _text(row.get("privilege")).upper()
        kind = _text(row.get("granted_to")).upper()
        grantee = _text(row.get("grantee_name"))
        if privilege in EXECUTION_PRIVILEGES and kind in _ROLE_GRANTEE_KINDS and grantee:
            roles.setdefault((grantee, privilege), {"role": grantee, "privilege": privilege, "granted_to": kind})

    _for_each_row(
        conn,
        f"SHOW GRANTS ON AGENT {_quoted_fqn(database, schema, name)}",  # nosec B608 — identifiers quoted
        handle,
        _warn_with(warnings, f"Could not list grants on Cortex Agent {database}.{schema}.{name}"),
    )
    return sorted(roles.values(), key=lambda r: (r["role"], r["privilege"]))


def _profile_display_name(profile: Any) -> str:
    if isinstance(profile, str):
        try:
            profile = json.loads(profile)
        except (json.JSONDecodeError, TypeError):
            return ""
    return _text(profile.get("display_name")) if isinstance(profile, dict) else ""


def list_cortex_agents(conn: Any, warnings: list[str], on_error: Any = None) -> list[dict[str, Any]]:
    """``SHOW AGENTS IN ACCOUNT`` rows (stored-case names), capped at ``MAX_CORTEX_AGENTS``."""
    rows: list[dict[str, Any]] = []
    _for_each_row(conn, "SHOW AGENTS IN ACCOUNT", rows.append, on_error or _warn_with(warnings, "Could not list Cortex Agents"))
    agents = [row for row in rows if _text(row.get("name")) and _text(row.get("database_name")) and _text(row.get("schema_name"))]
    if len(agents) > MAX_CORTEX_AGENTS:
        warnings.append(f"Cortex Agent inventory capped at {MAX_CORTEX_AGENTS} of {len(agents)} agents; the rest were not described.")
    return agents[:MAX_CORTEX_AGENTS]


def describe_cortex_agent(conn: Any, account: str, row: dict[str, Any], warnings: list[str]) -> dict[str, Any]:
    """One SHOW AGENTS row -> specification, declared tools and execution roles."""
    database, schema, name = _text(row.get("database_name")), _text(row.get("schema_name")), _text(row.get("name"))
    described = _describe(conn, database, schema, name, warnings)
    spec = described.get("agent_spec")
    tools = parse_agent_spec(spec) if spec not in (None, "") else None
    if tools is not None:
        spec_status = "described"
    elif described and spec in (None, ""):
        spec_status = "hidden"
    else:
        spec_status = "unavailable"
    return {
        "account": account,
        "database": database,
        "schema": schema,
        "name": name,
        "fqn": snowflake_stored_fqn(database, schema, name),
        "node_id": snowflake_cortex_agent_node_id(account, database, schema, name),
        "display_name": _profile_display_name(row.get("profile")) or name,
        "owner": _text(described.get("owner")) or _text(row.get("owner")),
        "is_secure": str(row.get("is_secure", "")).lower() == "true",
        "spec_status": spec_status,
        "tools": tools or [],
        "execution_roles": _execution_roles(conn, database, schema, name, warnings),
    }


def collect_cortex_agents(conn: Any, account: str, warnings: list[str]) -> list[dict[str, Any]]:
    return [describe_cortex_agent(conn, account, row, warnings) for row in list_cortex_agents(conn, warnings)]
