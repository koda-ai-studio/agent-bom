"""Map session calls to the flat OTLP span shape shared with the hosted trace connectors.

A session is an agent span; each call is a child span. MCP calls are tool
spans bound to their configured server. Built-in tools (shell, file edits)
keep ``tool.name`` for the OTLP parser but normalize as ``other`` so they are
never reported as uninventoried shadow tools. Command and path evidence is
redacted; arguments are mapped only with ``include_content``.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from agent_bom.runtime.agent_sessions.bindings import SessionBindings
from agent_bom.runtime.agent_sessions.records import SessionToolCall, parse_timestamp
from agent_bom.runtime.normalized_trace import AGENT_REF_KEY, INVENTORY_NODE_KEY, NORMALIZED_ATTRIBUTE, from_local_session, resource_ref
from agent_bom.security import sanitize_text

_MAX_EVIDENCE = 500
_MAX_ARGUMENTS = 20


def redact_path(path: str) -> str:
    home = str(Path.home())
    text = "~" + path[len(home) :] if home != "/" and (path == home or path.startswith(home + "/")) else path
    return sanitize_text(text, max_len=_MAX_EVIDENCE)


def _nanos(timestamp: str) -> str:
    moment = parse_timestamp(timestamp)
    return str(int(moment.timestamp() * 1_000_000) * 1000) if moment else ""


def _span(trace_id: str, span_id: str, parent: str, name: str, timestamp: str, attrs: dict[str, str], failed: bool) -> dict[str, Any]:
    span: dict[str, Any] = {
        "traceId": trace_id,
        "spanId": span_id,
        "parentSpanId": parent,
        "name": name,
        "status": {"code": 2 if failed else 0},
        "attributes": [{"key": key, "value": {"stringValue": value}} for key, value in attrs.items() if value],
    }
    if nanos := _nanos(timestamp):
        span["startTimeUnixNano"] = nanos
    return span


def _base_attrs(provider: str, name: str, native_type: str, session_id: str) -> dict[str, str]:
    return {
        "agent_bom.trace_provider": provider,
        "agent_bom.native_name": name,
        "agent_bom.native_type": native_type,
        "agent_bom.type_basis": "native",
        "agent_bom.native_session_id": session_id,
    }


def session_span(provider: str, agent_type: str, first: SessionToolCall, bindings: SessionBindings) -> dict[str, Any]:
    trace_id = f"{first.source}:{first.session_id}"
    agent_ref = bindings.agent_ref(agent_type)
    attrs = _base_attrs(provider, agent_type, "agent", first.session_id)
    attrs.update({"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": agent_type, AGENT_REF_KEY: agent_ref or ""})
    attrs["agent_bom.session.project_root"] = redact_path(first.project_root) if first.project_root else ""
    view: dict[str, Any] = {"kind": "agent", "trace_id": trace_id, "span_id": f"{trace_id}:session", "started": first.timestamp}
    view.update({"agent_name": agent_type, "agent_ref": agent_ref})
    attrs[NORMALIZED_ATTRIBUTE] = json.dumps(from_local_session(view, tenant_id="", source=first.source).to_dict(), sort_keys=True)
    return _span(trace_id, f"{trace_id}:session", "", f"{first.source}.agent.session", first.timestamp, attrs, False)


def _evidence_attrs(call: SessionToolCall) -> dict[str, str]:
    attrs = {"agent_bom.session.action": call.action}
    if call.command:
        attrs["agent_bom.session.command"] = sanitize_text(call.command, max_len=_MAX_EVIDENCE)
    if call.paths:
        attrs["agent_bom.session.paths"] = json.dumps([redact_path(path) for path in call.paths[:20]])
    if call.project_root:
        attrs["agent_bom.session.project_root"] = redact_path(call.project_root)
    if call.url and (host := resource_ref(call.url)):
        attrs["agent_bom.session.url_host"] = host
    return attrs


def _content_attrs(call: SessionToolCall) -> dict[str, str]:
    items = list(call.arguments.items())[:_MAX_ARGUMENTS]
    return {
        f"tool.input.{key}": sanitize_text(value if isinstance(value, str) else json.dumps(value, default=str), max_len=_MAX_EVIDENCE)
        for key, value in items
    }


def call_span(provider: str, agent_type: str, call: SessionToolCall, bindings: SessionBindings, *, include_content: bool) -> dict[str, Any]:
    trace_id = f"{call.source}:{call.session_id}"
    server = bindings.server(agent_type, call.server) if call.server else None
    agent_ref = server.agent_id if server else bindings.agent_ref(agent_type)
    tool_node = server.tool_node(call.tool) if server else None
    attrs = _base_attrs(provider, call.tool, "tool" if call.server else "builtin_tool", call.session_id)
    attrs.update({"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": call.tool, "tool.name": call.tool})
    attrs.update({"gen_ai.agent.name": agent_type, "mcp.server": call.server or "", AGENT_REF_KEY: agent_ref or ""})
    attrs[INVENTORY_NODE_KEY] = tool_node or ""
    attrs.update(_evidence_attrs(call))
    if include_content and call.arguments:
        attrs.update(_content_attrs(call))
    view = {
        "kind": "tool" if call.server else "other",
        "trace_id": trace_id,
        "span_id": f"{trace_id}:{call.call_id}",
        "parent_id": f"{trace_id}:session",
        "started": call.timestamp,
        "agent_name": agent_type,
        "agent_ref": agent_ref,
        "inventory_id": tool_node,
        "tool": call.tool,
        "server": server.server_id if server else None,
        "resources": (call.url,),
        "failed": call.failed,
    }
    attrs[NORMALIZED_ATTRIBUTE] = json.dumps(from_local_session(view, tenant_id="", source=call.source).to_dict(), sort_keys=True)
    name = f"{call.source}.tool.{call.tool}"
    return _span(trace_id, f"{trace_id}:{call.call_id}", f"{trace_id}:session", name, call.timestamp, attrs, call.failed)


def spans_for_calls(
    provider: str, agent_type: str, calls: Iterable[SessionToolCall], bindings: SessionBindings, *, include_content: bool
) -> list[dict[str, Any]]:
    spans: list[dict[str, Any]] = []
    sessions: set[str] = set()
    for call in calls:
        if call.session_id not in sessions:
            sessions.add(call.session_id)
            spans.append(session_span(provider, agent_type, call, bindings))
        spans.append(call_span(provider, agent_type, call, bindings, include_content=include_content))
    return spans
