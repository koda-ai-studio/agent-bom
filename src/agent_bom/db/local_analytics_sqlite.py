"""SQLite file-level helpers for the local scan analytics mirror."""

from __future__ import annotations

import sqlite3
from typing import Any

_AUTO_VACUUM_MODES = {0: "none", 1: "full", 2: "incremental"}


def page_stats(conn: sqlite3.Connection) -> dict[str, Any]:
    page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
    free_pages = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
    page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
    mode = int(conn.execute("PRAGMA auto_vacuum").fetchone()[0])
    return {
        "page_size": page_size,
        "page_count": page_count,
        "free_pages": free_pages,
        "free_bytes": free_pages * page_size,
        "live_bytes": (page_count - free_pages) * page_size,
        "auto_vacuum": _AUTO_VACUUM_MODES.get(mode, str(mode)),
    }


def release_free_pages(conn: sqlite3.Connection) -> None:
    # The pragma yields one row per freed page; draining the cursor frees the whole list.
    # It is a no-op unless the file is in incremental auto-vacuum mode.
    conn.execute("PRAGMA incremental_vacuum").fetchall()


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone()
    return row is not None


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
