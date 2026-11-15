"""PRAGMA busy_timeout takes no bind parameters, so every caller goes through one int-coercing helper."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agent_bom.api.storage.sqlite_connection import set_busy_timeout

ROOT = Path(__file__).resolve().parents[1]


def test_sets_the_busy_timeout() -> None:
    conn = sqlite3.connect(":memory:")
    set_busy_timeout(conn, 2500)
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 2500


def test_rejects_non_numeric_text() -> None:
    conn = sqlite3.connect(":memory:")
    with pytest.raises(ValueError):
        set_busy_timeout(conn, "1; DROP TABLE x")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "relative",
    [
        "src/agent_bom/api/storage/sqlite_connection.py",
        "src/agent_bom/api/sqlite_key_store.py",
        "src/agent_bom/api/idempotency_store.py",
        "src/agent_bom/api/audit_log.py",
        "src/agent_bom/storage/sqlite_wal.py",
    ],
)
def test_no_uncoerced_busy_timeout_pragma(relative: str) -> None:
    text = (ROOT / relative).read_text(encoding="utf-8")
    for line in text.splitlines():
        if "PRAGMA busy_timeout={" in line:
            assert "={int(" in line or "={_" in line.split("PRAGMA busy_timeout")[1][:4], line
