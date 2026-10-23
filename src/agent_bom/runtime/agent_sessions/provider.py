"""Local trace providers: session histories in, ``{"spans": [...]}`` out.

Same contract as the hosted connectors, so ``otel_ingest``, the native trace
importer and the graph's runtime projection consume them unchanged. These
providers read the caller's own files and therefore run only in local CLI or
stdio MCP processes; the control-plane pull route rejects them.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agent_bom.runtime.agent_sessions import PROVIDER_AGENT_TYPES, SessionBounds, read_session_calls
from agent_bom.runtime.agent_sessions.bindings import SessionBindings
from agent_bom.runtime.agent_sessions.spans import spans_for_calls

DEFAULT_WINDOW_DAYS = 30


def default_since(days: int = DEFAULT_WINDOW_DAYS) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=max(1, days))


def local_session_connectors() -> list[dict[str, Any]]:
    return [{"name": name, "kind": "local_session_history", "auth_fields": [], "supports_content": True} for name in PROVIDER_AGENT_TYPES]


def fetch_local_session_traces(
    provider: str,
    *,
    home: Path | None = None,
    since: datetime | None = None,
    project: str | None = None,
    bindings: SessionBindings | None = None,
    include_content: bool = False,
    bounds: SessionBounds | None = None,
) -> dict[str, Any]:
    """Read one provider's local history and return flat spans plus read accounting."""
    calls, stats = read_session_calls(provider, home=home, since=since or default_since(), project=project, bounds=bounds)
    agent_type = PROVIDER_AGENT_TYPES[provider]
    spans = spans_for_calls(provider, agent_type, calls, bindings or SessionBindings(), include_content=include_content)
    return {"spans": spans, "read": stats.to_dict()}
