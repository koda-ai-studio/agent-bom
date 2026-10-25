"""Rebuild a SQLite table under a wider primary key, keeping every row, in one transaction."""

from __future__ import annotations

import sqlite3


def primary_key_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()  # nosec B608 - callers pass static table names
    return [str(row[1]) for row in sorted((row for row in rows if row[5]), key=lambda row: row[5])]


def rekey_table(conn: sqlite3.Connection, table: str, *, key: list[str], create_sql: str, columns: str) -> bool:
    """Recreate *table* from ``create_sql`` (a ``{table}`` template) when its primary key is not *key*.

    Idempotent and a no-op on a fresh table. The caller guarantees the old key
    is a subset of the new one, so every existing row fits. Returns whether a
    rebuild ran.
    """
    if primary_key_columns(conn, table) == key:
        return False
    scratch = f"{table}_rekey_migration"
    conn.commit()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if primary_key_columns(conn, table) != key:
            conn.execute(f"DROP TABLE IF EXISTS {scratch}")
            conn.execute(create_sql.format(table=scratch))
            conn.execute(f"INSERT INTO {scratch} ({columns}) SELECT {columns} FROM {table}")  # nosec B608 - static names
            conn.execute(f"DROP TABLE {table}")
            conn.execute(f"ALTER TABLE {scratch} RENAME TO {table}")
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return True
