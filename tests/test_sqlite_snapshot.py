"""SQLite byte comparisons flush the WAL first, so a closing writer cannot change the result."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from tests.sqlite_snapshot import checkpointed_bytes


def test_checkpointed_bytes_are_unchanged_when_the_writer_closes(tmp_path: Path) -> None:
    path = tmp_path / "wal.db"
    writer = sqlite3.connect(path)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("CREATE TABLE t (v TEXT)")
    writer.execute("INSERT INTO t VALUES ('x')")
    writer.commit()
    raw, flushed = path.read_bytes(), checkpointed_bytes(path)
    writer.close()
    assert raw != flushed, "a raw read sees the file before its WAL is applied"
    assert path.read_bytes() == flushed


def test_recovery_tests_do_not_read_sqlite_bytes_directly() -> None:
    root = Path(__file__).parent
    recovery_tests = [*root.glob("test_*recovery*.py"), root / "test_control_plane_imports.py"]
    offenders = [p.name for p in recovery_tests if "before = path.read_bytes()" in p.read_text(encoding="utf-8")]
    assert offenders == []
