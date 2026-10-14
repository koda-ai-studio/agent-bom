"""Cortex Agent observability spans mapped to the normalized trace-event shape.

Spans are read per agent through ``SNOWFLAKE.LOCAL.GET_AI_OBSERVABILITY_EVENTS``
(database, schema, agent name, ``'CORTEX AGENT'``), which returns event-table
rows (``TIMESTAMP``, ``START_TIMESTAMP``, ``TRACE``, ``RESOURCE_ATTRIBUTES``,
``RECORD``, ``RECORD_ATTRIBUTES``). Raw prompts, tool inputs and tool
outputs are never kept: content is reduced to a SHA-256 digest and the user name
to the tenant-keyed principal digest.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from agent_bom.canonical_ids import snowflake_cortex_agent_node_id, snowflake_cortex_tool_node_id, snowflake_stored_fqn

from ..snowflake_common import _CONTROL_CHAR_RE, _parse_json_object
from ._base import _for_each_row, _warn_with

SOURCE = "snowflake_cortex"
MAX_SPANS_PER_AGENT = 2000

NORMALIZED_FIELDS: tuple[str, ...] = (
    "tenant_id",
    "source",
    "source_trace_id",
    "source_span_id",
    "parent_span_id",
    "started_at",
    "ended_at",
    "kind",
    "agent_name",
    "agent_ref",
    "model_provider",
    "model_name",
    "tool_name",
    "mcp_server_ref",
    "resource_refs",
    "principal_hash",
    "role_name",
    "credential_ref",
    "input_tokens",
    "output_tokens",
    "cost_usd",
    "status",
    "signals",
    "content_sha256",
    "match_method",
    "match_node_id",
)

# Event-table field -> normalized field. ``documented`` fields are named in the
# Snowflake event-table / AI observability references; ``observed_key`` fields
# are matched by attribute-key suffix because the Cortex Agent span attribute
# names are not published, so they stay None when a span does not carry them.
FIELD_MAP: tuple[tuple[str, str, str], ...] = (
    ("TRACE:trace_id", "source_trace_id", "documented"),
    ("TRACE:span_id", "source_span_id", "documented"),
    ("RECORD:parent_span_id", "parent_span_id", "documented"),
    ("START_TIMESTAMP", "started_at", "documented"),
    ("TIMESTAMP", "ended_at", "documented"),
    ("RECORD:name", "kind", "documented"),
    ("RECORD:status.code", "status", "documented"),
    ("RESOURCE_ATTRIBUTES:snow.user.name | db.user", "principal_hash", "documented"),
    ("RESOURCE_ATTRIBUTES:snow.session.role.primary.name", "role_name", "documented"),
    ("RESOURCE_ATTRIBUTES:snow.warehouse.name", "resource_refs", "documented"),
    ("RECORD_ATTRIBUTES:snow.ai.observability.agent.planning.model", "model_name", "documented"),
    ("GET_AI_OBSERVABILITY_EVENTS(database, schema, agent_name)", "agent_name / agent_ref", "documented"),
    ("RECORD_ATTRIBUTES:*.tool.name | *tool_name", "tool_name", "observed_key"),
    ("RECORD_ATTRIBUTES:*prompt_tokens | *input_tokens", "input_tokens", "observed_key"),
    ("RECORD_ATTRIBUTES:*completion_tokens | *output_tokens", "output_tokens", "observed_key"),
    (
        "RECORD_ATTRIBUTES:*input | *query_text | *prompt | *arguments ; *output | *retrieved_contexts | *response | *result",
        "content_sha256",
        "observed_key",
    ),
)
# The event table carries no cost, MCP server, provider or credential fields;
# credits live in ACCOUNT_USAGE.CORTEX_AGENT_USAGE_HISTORY.TOKEN_CREDITS.
UNSUPPLIED_FIELDS = ("model_provider", "mcp_server_ref", "credential_ref", "cost_usd")
# Sourced from the span but left empty until the shared tenant-keyed digest is wired in.
PENDING_FIELDS = ("principal_hash",)

_PLANNING_MODEL = "snow.ai.observability.agent.planning.model"
_TOOL_NAME_RE = re.compile(r"(^|[._])tool[._]name$", re.IGNORECASE)
_INPUT_TOKENS_RE = re.compile(r"(^|[._])(prompt|input)_tokens$", re.IGNORECASE)
_OUTPUT_TOKENS_RE = re.compile(r"(^|[._])(completion|output)_tokens$", re.IGNORECASE)
_INPUT_RE = re.compile(r"(^|[._])(input|query_text|prompt|arguments)s?$", re.IGNORECASE)
_OUTPUT_RE = re.compile(r"(^|[._])(output|retrieved_contexts|response|result)s?$", re.IGNORECASE)


def _sql_string(value: str) -> str:
    if _CONTROL_CHAR_RE.search(value):
        raise ValueError("unsafe Snowflake string literal")
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def _text(value: Any) -> str:
    return str(value).strip() if value not in (None, "") else ""


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _first(attrs: dict[str, Any], pattern: re.Pattern[str]) -> Any:
    for key in sorted(attrs):
        if pattern.search(key) and attrs[key] not in (None, ""):
            return attrs[key]
    return None


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _iso(value: Any) -> str | None:
    if value in (None, ""):
        return None
    isoformat = getattr(value, "isoformat", None)
    return isoformat() if callable(isoformat) else str(value)


def _kind(span_name: str, attrs: dict[str, Any], tool_name: str, parent: str) -> str:
    lowered = span_name.lower()
    keys = " ".join(attrs).lower()
    if "mcp" in lowered:
        return "mcp"
    if tool_name or "tool" in lowered:
        return "tool"
    if "retriev" in lowered or "search" in lowered or "retrieval." in keys:
        return "retrieval"
    if any(token in lowered for token in ("planning", "llm", "generation", "inference", "model")) or _PLANNING_MODEL in attrs:
        return "llm"
    if not parent:
        return "agent"
    return "other"


def _content_digest(attrs: dict[str, Any]) -> str | None:
    """``sha256(json.dumps([input, output]))`` — the shared normalized-event content digest."""
    content_input, content_output = _first(attrs, _INPUT_RE), _first(attrs, _OUTPUT_RE)
    if content_input is None and content_output is None:
        return None
    return _sha256(json.dumps([content_input, content_output], sort_keys=True, default=str))


def _principal_digest(tenant_id: str | None, user_id: str) -> str | None:
    """Tenant-keyed principal digest; empty until the shared keyed digest is wired in.

    A plain hash of a user name is dictionary-reversible and joins across
    tenants, so no local fallback is computed.
    """
    del tenant_id, user_id
    return None


def normalize_cortex_span(
    row: dict[str, Any],
    *,
    account: str,
    database: str,
    schema: str,
    agent_name: str,
    declared_tools: set[str] | frozenset[str] = frozenset(),
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """One ``GET_AI_OBSERVABILITY_EVENTS`` span row -> normalized trace event (no raw content)."""
    trace = _parse_json_object(row.get("trace"))
    record = _parse_json_object(row.get("record"))
    attrs = _parse_json_object(row.get("record_attributes"))
    resource = _parse_json_object(row.get("resource_attributes"))
    status_obj = record.get("status") if isinstance(record.get("status"), dict) else {}
    status_code = _text(status_obj.get("code") if status_obj else record.get("status")).upper()
    span_name = _text(record.get("name"))
    parent = _text(record.get("parent_span_id"))
    agent_ref = snowflake_cortex_agent_node_id(account, database, schema, agent_name)

    tool_name = _text(_first(attrs, _TOOL_NAME_RE))
    if not tool_name and span_name in declared_tools:
        tool_name = span_name
    kind = _kind(span_name, attrs, tool_name, parent)
    user = _text(resource.get("snow.user.name")) or _text(resource.get("db.user"))
    warehouse = _text(resource.get("snow.warehouse.name"))
    signals: set[str] = set()
    status = "error" if status_code == "STATUS_CODE_ERROR" else "ok"
    if status == "error":
        signals.add("error")
    content_sha256 = _content_digest(attrs)
    if content_sha256:
        signals.add("content_hashed")

    if tool_name and tool_name in declared_tools:
        match_method, match_node_id = "exact", snowflake_cortex_tool_node_id(agent_ref, agent_name, tool_name)
    elif tool_name:
        match_method, match_node_id = "none", None
        signals.add("undeclared_tool")
    else:
        match_method, match_node_id = "exact", agent_ref

    return {
        "tenant_id": tenant_id,
        "source": SOURCE,
        "source_trace_id": _text(trace.get("trace_id")) or None,
        "source_span_id": _text(trace.get("span_id")) or None,
        "parent_span_id": parent or None,
        "started_at": _iso(row.get("start_timestamp")),
        "ended_at": _iso(row.get("timestamp")),
        "kind": kind,
        "agent_name": snowflake_stored_fqn(database, schema, agent_name),
        "agent_ref": agent_ref,
        "model_provider": None,
        "model_name": _text(attrs.get(_PLANNING_MODEL)) or None,
        "tool_name": tool_name or None,
        "mcp_server_ref": None,
        "resource_refs": sorted({f"warehouse:{warehouse}"} if warehouse else set()),
        "principal_hash": _principal_digest(tenant_id, user) if user else None,
        "role_name": _text(resource.get("snow.session.role.primary.name")) or None,
        "credential_ref": None,
        "input_tokens": _int_or_none(_first(attrs, _INPUT_TOKENS_RE)),
        "output_tokens": _int_or_none(_first(attrs, _OUTPUT_TOKENS_RE)),
        "cost_usd": None,
        "status": status,
        "signals": sorted(signals),
        "content_sha256": content_sha256,
        "match_method": match_method,
        "match_node_id": match_node_id,
    }


def fetch_cortex_agent_spans(
    conn: Any,
    agent: dict[str, Any],
    days: int,
    warnings: list[str],
    *,
    tenant_id: str | None = None,
) -> list[dict[str, Any]]:
    """Normalized span events for one Cortex Agent over the last ``days`` days."""
    database, schema, name = _text(agent.get("database")), _text(agent.get("schema")), _text(agent.get("name"))
    if not (database and schema and name):
        return []
    try:
        args = ", ".join(_sql_string(part) for part in (database, schema, name))
    except ValueError:
        warnings.append(f"Skipped observability events for Cortex Agent with unsafe name {database}.{schema}")
        return []
    declared = frozenset(_text(tool.get("name")) for tool in agent.get("tools") or [] if isinstance(tool, dict))
    events: list[dict[str, Any]] = []
    _for_each_row(
        conn,
        "SELECT timestamp, start_timestamp, trace, resource_attributes, record, record_attributes "
        f"FROM TABLE(SNOWFLAKE.LOCAL.GET_AI_OBSERVABILITY_EVENTS({args}, 'CORTEX AGENT')) "  # nosec B608 — literals escaped
        "WHERE record_type = 'SPAN' "
        f"AND timestamp >= DATEADD(day, -{int(days)}, CURRENT_TIMESTAMP()) "  # nosec B608 — days is int
        "ORDER BY timestamp DESC "
        f"LIMIT {MAX_SPANS_PER_AGENT + 1}",
        lambda row: events.append(
            normalize_cortex_span(
                row,
                account=_text(agent.get("account")),
                database=database,
                schema=schema,
                agent_name=name,
                declared_tools=declared,
                tenant_id=tenant_id,
            )
        ),
        _warn_with(warnings, f"Could not read observability events for Cortex Agent {database}.{schema}.{name}"),
    )
    if len(events) > MAX_SPANS_PER_AGENT:
        warnings.append(f"Observability spans for Cortex Agent {database}.{schema}.{name} capped at the newest {MAX_SPANS_PER_AGENT}.")
    return events[:MAX_SPANS_PER_AGENT]
