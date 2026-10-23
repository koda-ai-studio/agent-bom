"""The provider-neutral tool call read from a local coding-agent session."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

ACTIONS = ("exec", "read", "write", "fetch", "mcp", "search", "agent", "other")


@dataclass(frozen=True)
class SessionToolCall:
    """One tool call. Raw command/path text stays in memory; spans redact it."""

    source: str
    session_id: str
    call_id: str
    timestamp: str
    tool: str
    action: str
    project_root: str = ""
    server: str | None = None
    command: str | None = None
    paths: tuple[str, ...] = ()
    url: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)
    failed: bool = False


@dataclass
class SessionReadStats:
    """What was read and what the bounds or window excluded; nothing is dropped silently."""

    history_found: bool = False
    files_read: int = 0
    files_skipped_cap: int = 0
    files_skipped_window: int = 0
    lines_read: int = 0
    malformed_lines: int = 0
    oversized_lines: int = 0
    lines_capped_files: int = 0
    bytes_read: int = 0
    bytes_capped: bool = False
    out_of_window: int = 0
    project_filtered: int = 0
    calls: int = 0

    @property
    def truncated(self) -> bool:
        return bool(self.files_skipped_cap or self.lines_capped_files or self.bytes_capped)

    def to_dict(self) -> dict[str, Any]:
        payload = {key: value for key, value in self.__dict__.items()}
        payload["truncated"] = self.truncated
        return payload


def as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_text(value: object) -> str:
    return value if isinstance(value, str) else ""


def parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment.astimezone(timezone.utc) if moment.tzinfo else None


def under_root(path: str, root: str) -> bool:
    if not root or not path.startswith("/"):
        return True
    root = root.rstrip("/") or "/"
    return path == root or path.startswith(root + "/")
