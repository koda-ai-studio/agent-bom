"""Bounded streaming JSONL reads: capped files, lines and bytes; never a whole file in memory."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from agent_bom.runtime.agent_sessions.records import SessionReadStats


@dataclass(frozen=True)
class SessionBounds:
    max_files: int = 500
    max_lines_per_file: int = 50_000
    max_line_bytes: int = 1_000_000
    max_total_bytes: int = 256 * 1024 * 1024


def session_files(root: Path, pattern: str, since: datetime, bounds: SessionBounds, stats: SessionReadStats) -> list[Path]:
    """Newest-first files modified inside the window, capped at ``max_files``."""
    if not root.is_dir():
        return []
    stats.history_found = True
    floor = since.timestamp()
    dated: list[tuple[float, Path]] = []
    for path in root.glob(pattern):
        try:
            mtime = path.stat().st_mtime if path.is_file() and not path.is_symlink() else None
        except OSError:
            mtime = None
        if mtime is None:
            continue
        if mtime < floor:
            stats.files_skipped_window += 1
            continue
        dated.append((mtime, path))
    dated.sort(key=lambda item: (-item[0], str(item[1])))
    stats.files_skipped_cap += max(0, len(dated) - bounds.max_files)
    return [path for _, path in dated[: bounds.max_files]]


def iter_records(path: Path, bounds: SessionBounds, stats: SessionReadStats) -> Iterator[dict[str, Any]]:
    """Yield JSON objects line by line; malformed and oversized lines are counted and skipped."""
    if stats.bytes_read >= bounds.max_total_bytes:
        stats.bytes_capped = True
        stats.files_skipped_cap += 1
        return
    try:
        handle = path.open("rb")
    except OSError:
        return
    stats.files_read += 1
    with handle:
        for count in range(bounds.max_lines_per_file + 1):
            if count == bounds.max_lines_per_file:
                if handle.readline(1):
                    stats.lines_capped_files += 1
                return
            if stats.bytes_read >= bounds.max_total_bytes:
                stats.bytes_capped = True
                return
            line = handle.readline(bounds.max_line_bytes + 1)
            if not line:
                return
            stats.bytes_read += len(line)
            if len(line) > bounds.max_line_bytes and not line.endswith(b"\n"):
                stats.oversized_lines += 1
                _discard_rest_of_line(handle, bounds, stats)
                continue
            record = _decode(line, stats)
            if record is not None:
                yield record


def _discard_rest_of_line(handle: Any, bounds: SessionBounds, stats: SessionReadStats) -> None:
    while stats.bytes_read < bounds.max_total_bytes:
        chunk = handle.readline(bounds.max_line_bytes)
        stats.bytes_read += len(chunk)
        if not chunk or chunk.endswith(b"\n"):
            return
    stats.bytes_capped = True


def _decode(line: bytes, stats: SessionReadStats) -> dict[str, Any] | None:
    stats.lines_read += 1
    text = line.strip()
    if not text:
        return None
    try:
        record = json.loads(text)
    except (ValueError, RecursionError):
        stats.malformed_lines += 1
        return None
    if not isinstance(record, dict):
        stats.malformed_lines += 1
        return None
    return record
