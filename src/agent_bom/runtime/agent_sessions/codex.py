"""Codex session histories: ``~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl``.

``session_meta`` and ``turn_context`` carry the working directory. Completed
work arrives as ``event_msg`` / ``item_completed`` items (``CommandExecution``,
``FileChange``, ``McpToolCall``, ``WebSearch``). The matching ``function_call``
response items repeat MCP calls with the same id, so only completed items are
counted and ids are de-duplicated.
"""

from __future__ import annotations

import shlex
from collections.abc import Iterable, Iterator
from typing import Any

from agent_bom.runtime.agent_sessions.records import SessionToolCall, as_dict, as_text, parse_timestamp

SOURCE = "codex"
ROOT = (".codex", "sessions")
PATTERN = "**/rollout-*.jsonl"
_SHELLS = {"sh", "bash", "zsh", "fish"}


def _command_text(command: object) -> str | None:
    if isinstance(command, str):
        return command
    if not isinstance(command, list) or not all(isinstance(part, str) for part in command):
        return None
    # ["/bin/zsh", "-lc", "<script>"] wraps the real command line.
    if len(command) == 3 and command[0].rsplit("/", 1)[-1] in _SHELLS and command[1] in {"-c", "-lc"}:
        return command[2]
    return shlex.join(command)


def _call_fields(item: dict[str, Any], cwd: str) -> dict[str, Any] | None:
    kind = item.get("type")
    if kind == "CommandExecution":
        command = _command_text(item.get("command"))
        item_cwd = as_text(item.get("cwd")) or cwd
        return {"tool": "exec", "action": "exec", "command": command, "project_root": item_cwd} if command else None
    if kind == "FileChange" and isinstance(item.get("changes"), dict):
        paths = tuple(path for path in item["changes"] if isinstance(path, str) and path)
        return {"tool": "apply_patch", "action": "write", "paths": paths[:50]} if paths else None
    if kind == "McpToolCall" and isinstance(item.get("server"), str) and isinstance(item.get("tool"), str):
        arguments = as_dict(item.get("arguments"))
        return {"tool": item["tool"], "action": "mcp", "server": item["server"], "arguments": arguments}
    if kind == "WebSearch":
        return {"tool": "web_search", "action": "fetch"}
    return None


def calls_from_records(records: Iterable[dict[str, Any]]) -> Iterator[SessionToolCall]:
    session_id, cwd = "", ""
    seen: set[str] = set()
    for record in records:
        payload = as_dict(record.get("payload"))
        if record.get("type") == "session_meta":
            session_id = str(payload.get("id") or payload.get("session_id") or session_id)
            cwd = as_text(payload.get("cwd")) or cwd
            continue
        if record.get("type") == "turn_context" and as_text(payload.get("cwd")):
            cwd = as_text(payload.get("cwd"))
            continue
        if record.get("type") != "event_msg" or payload.get("type") != "item_completed":
            continue
        item = as_dict(payload.get("item"))
        item_id, moment = item.get("id"), parse_timestamp(record.get("timestamp"))
        fields = _call_fields(item, cwd)
        if fields is None or not isinstance(item_id, str) or not item_id or item_id in seen or moment is None:
            continue
        seen.add(item_id)
        fields.setdefault("project_root", cwd)
        yield SessionToolCall(
            source=SOURCE,
            session_id=session_id or str(payload.get("thread_id") or ""),
            call_id=item_id,
            timestamp=moment.isoformat(),
            failed=str(item.get("status") or "").lower() in {"failed", "error"},
            **fields,
        )
