"""Read the redacted, safe attribute subset back out of session spans."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from agent_bom.runtime.agent_sessions.records import parse_timestamp


@dataclass(frozen=True)
class CallView:
    provider: str
    agent: str
    session_id: str
    timestamp: str
    tool: str
    server: str
    action: str
    command: str
    paths: tuple[str, ...]
    project_root: str


def _attrs(span: dict[str, Any]) -> dict[str, str]:
    return {
        item["key"]: item["value"]["stringValue"]
        for item in span.get("attributes") or []
        if isinstance(item, dict) and isinstance(item.get("value"), dict) and isinstance(item["value"].get("stringValue"), str)
    }


def _timestamp(span: dict[str, Any]) -> str:
    try:
        nanos = int(span.get("startTimeUnixNano") or 0)
    except (TypeError, ValueError):
        return ""
    return datetime.fromtimestamp(nanos / 1e9, tz=timezone.utc).isoformat() if nanos else ""


def _paths(raw: str) -> tuple[str, ...]:
    try:
        value = json.loads(raw) if raw else []
    except ValueError:
        return ()
    return tuple(str(item) for item in value if isinstance(item, str)) if isinstance(value, list) else ()


def call_views(spans: Iterable[dict[str, Any]]) -> Iterator[CallView]:
    for span in spans:
        attrs = _attrs(span)
        if attrs.get("gen_ai.operation.name") != "execute_tool":
            continue
        yield CallView(
            provider=attrs.get("agent_bom.trace_provider", ""),
            agent=attrs.get("gen_ai.agent.name", ""),
            session_id=attrs.get("agent_bom.native_session_id", ""),
            timestamp=_timestamp(span),
            tool=attrs.get("tool.name", ""),
            server=attrs.get("mcp.server", ""),
            action=attrs.get("agent_bom.session.action", "other"),
            command=attrs.get("agent_bom.session.command", ""),
            paths=_paths(attrs.get("agent_bom.session.paths", "")),
            project_root=attrs.get("agent_bom.session.project_root", ""),
        )


def later(first: str, second: str) -> str:
    a, b = parse_timestamp(first), parse_timestamp(second)
    if a is None:
        return second
    if b is None:
        return first
    return first if a >= b else second
