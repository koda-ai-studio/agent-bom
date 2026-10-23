"""Claude Code session histories: ``~/.claude/projects/<project>/<session>.jsonl``.

Only ``type == "assistant"`` records carry the agent's own ``tool_use`` blocks;
request-blob records repeat them and are ignored. A tool use is identified by
its block ``id`` so streamed duplicates count once.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from agent_bom.runtime.agent_sessions.records import SessionToolCall, as_dict, as_text, parse_timestamp

SOURCE = "claude_code"
ROOT = (".claude", "projects")
PATTERN = "**/*.jsonl"

_EXEC = {"Bash", "BashOutput", "PowerShell"}
_READ = {"Read", "Grep", "Glob", "NotebookRead", "LS"}
_WRITE = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
_FETCH = {"WebFetch", "WebSearch"}
_AGENT = {"Agent", "Task"}
_PATH_KEYS = ("file_path", "notebook_path", "path")


def split_mcp_name(name: str) -> tuple[str, str] | None:
    """``mcp__<server>__<tool>``; the server segment ends at the first double underscore."""
    if not name.startswith("mcp__"):
        return None
    server, separator, tool = name[len("mcp__") :].partition("__")
    return (server, tool) if separator and server and tool else None


def _action(name: str) -> str:
    for action, names in (("exec", _EXEC), ("read", _READ), ("write", _WRITE), ("fetch", _FETCH), ("agent", _AGENT)):
        if name in names:
            return action
    return "other"


def _call(record: dict[str, Any], block: dict[str, Any]) -> SessionToolCall | None:
    name, call_id = block.get("name"), block.get("id")
    moment = parse_timestamp(record.get("timestamp"))
    if not isinstance(name, str) or not name or not isinstance(call_id, str) or not call_id or moment is None:
        return None
    tool_input = as_dict(block.get("input"))
    mcp = split_mcp_name(name)
    command = tool_input.get("command")
    url = tool_input.get("url")
    return SessionToolCall(
        source=SOURCE,
        session_id=str(record.get("sessionId") or ""),
        call_id=call_id,
        timestamp=moment.isoformat(),
        tool=mcp[1] if mcp else name,
        action="mcp" if mcp else _action(name),
        project_root=as_text(record.get("cwd")),
        server=mcp[0] if mcp else None,
        command=command if isinstance(command, str) and not mcp else None,
        paths=tuple(value for key in _PATH_KEYS if isinstance(value := tool_input.get(key), str) and value) if not mcp else (),
        url=url if isinstance(url, str) else None,
        arguments=tool_input if mcp else {},
    )


def calls_from_records(records: Iterable[dict[str, Any]]) -> Iterator[SessionToolCall]:
    seen: set[str] = set()
    for record in records:
        message = record.get("message")
        if record.get("type") != "assistant" or not isinstance(message, dict) or not isinstance(message.get("content"), list):
            continue
        for block in message["content"]:
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue
            call = _call(record, block)
            if call is not None and call.call_id not in seen:
                seen.add(call.call_id)
                yield call
