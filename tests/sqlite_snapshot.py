"""Read a SQLite file's bytes without a pending WAL rewriting them later."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path


def checkpointed_bytes(path: Path) -> bytes:
    """An open writer can close at any time and checkpoint into the file, so flush first."""
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    return path.read_bytes()
