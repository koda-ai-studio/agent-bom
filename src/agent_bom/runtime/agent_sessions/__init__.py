"""Local coding-agent session histories as a trace source (Claude Code, Codex).

Files are read locally, bounded and streamed. Nothing is sent anywhere; the
calls become the same flat span shape the hosted trace connectors produce.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from agent_bom.runtime.agent_sessions import claude_code, codex
from agent_bom.runtime.agent_sessions.reader import SessionBounds, iter_records, session_files
from agent_bom.runtime.agent_sessions.records import SessionReadStats, SessionToolCall, parse_timestamp, under_root

CLAUDE_CODE_SESSIONS = "claude-code-sessions"
CODEX_SESSIONS = "codex-sessions"
_READERS = {CLAUDE_CODE_SESSIONS: claude_code, CODEX_SESSIONS: codex}
LOCAL_SESSION_PROVIDERS = tuple(_READERS)
PROVIDER_AGENT_TYPES = {CLAUDE_CODE_SESSIONS: "claude-code", CODEX_SESSIONS: "codex-cli"}
SOURCE_PROVIDERS = {claude_code.SOURCE: CLAUDE_CODE_SESSIONS, codex.SOURCE: CODEX_SESSIONS}


def _in_scope(call: SessionToolCall, since: datetime, project: str | None, stats: SessionReadStats) -> bool:
    moment = parse_timestamp(call.timestamp)
    if moment is None or moment < since:
        stats.out_of_window += 1
        return False
    if project and not (call.project_root and under_root(call.project_root, project)):
        stats.project_filtered += 1
        return False
    return True


def iter_session_calls(
    provider: str, *, home: Path, since: datetime, project: str | None, bounds: SessionBounds, stats: SessionReadStats
) -> Iterator[SessionToolCall]:
    module = _READERS[provider]
    root = home.joinpath(*module.ROOT)
    for path in session_files(root, module.PATTERN, since, bounds, stats):
        for call in module.calls_from_records(iter_records(path, bounds, stats)):
            if _in_scope(call, since, project, stats):
                stats.calls += 1
                yield call


def read_session_calls(
    provider: str,
    *,
    home: Path | None = None,
    since: datetime,
    project: str | None = None,
    bounds: SessionBounds | None = None,
) -> tuple[list[SessionToolCall], SessionReadStats]:
    """All in-window calls for one provider plus the read accounting."""
    if provider not in _READERS:
        raise ValueError(f"unknown local session provider {provider!r}")
    stats = SessionReadStats()
    resolved_project = str(Path(project).expanduser().resolve()) if project else None
    calls = list(
        iter_session_calls(
            provider, home=home or Path.home(), since=since, project=resolved_project, bounds=bounds or SessionBounds(), stats=stats
        )
    )
    return calls, stats


__all__ = [
    "CLAUDE_CODE_SESSIONS",
    "CODEX_SESSIONS",
    "LOCAL_SESSION_PROVIDERS",
    "PROVIDER_AGENT_TYPES",
    "SOURCE_PROVIDERS",
    "SessionBounds",
    "SessionReadStats",
    "SessionToolCall",
    "read_session_calls",
]
