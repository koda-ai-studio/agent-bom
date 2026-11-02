"""Validate SQL identifiers that local stores interpolate into DDL and PRAGMA text.

SQLite cannot bind table or column names as parameters, so helpers that take
a table name build ``PRAGMA table_info(<table>)`` / ``ALTER TABLE <table>``
text. Callers pass static names today; validating at the helper keeps that
true when a new caller arrives.
"""

from __future__ import annotations

import re

_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_COLUMN_LIST_SPLIT = re.compile(r"\s*,\s*")


def validate_sql_identifier(name: str) -> str:
    """Return ``name`` when it is a plain unquoted identifier, else raise ``ValueError``."""
    if not isinstance(name, str) or not _IDENTIFIER_RE.fullmatch(name):
        raise ValueError("SQL identifier must match [A-Za-z_][A-Za-z0-9_]* (max 128 characters)")
    return name


def validate_sql_column_list(columns: str) -> str:
    """Return ``columns`` when it is a comma-separated list of plain identifiers."""
    if not isinstance(columns, str) or not columns.strip():
        raise ValueError("SQL column list must name at least one column")
    for column in _COLUMN_LIST_SPLIT.split(columns.strip()):
        validate_sql_identifier(column)
    return columns
