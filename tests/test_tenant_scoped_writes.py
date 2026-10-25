"""Writes to tenant-keyed tables name the tenant: an UPDATE or DELETE by id alone can rewrite another tenant's row.

Companion to ``test_tenant_key_invariant``: that guard proves every key carries
the tenant; this one proves every keyed write uses it. Time-based sweeps
(``WHERE expires_at < ?``), one-off column backfills with no id equality, and ids
``test_tenant_key_invariant.GLOBAL_KEYS`` documents as globally unique are not flagged.
SQLite statements only: Postgres writes run under row-level security, which the
invariant suite proves separately.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from tests.test_tenant_key_invariant import GLOBAL_KEYS

ROOT = Path(__file__).resolve().parents[1]
STORE_DIRS = [ROOT / "src/agent_bom/api", ROOT / "src/agent_bom/db"]
TENANT = re.compile(r"\b(?:tenant_id|team_id)\b")
CREATE = re.compile(r"CREATE TABLE(?: IF NOT EXISTS)?\s+(\w+)\s*\((.*)\)", re.S | re.I)
KEYED_PK = re.compile(r"PRIMARY KEY\s*\(([^)]*)\)", re.I)
WRITE = re.compile(r"^\s*(?:UPDATE\s+(\w+)\s+SET|DELETE\s+FROM\s+(\w+))\b(.*)$", re.S | re.I)
ID_EQUALITY = re.compile(r"\b(\w*id|\w*_key|\w*digest|\w*hash)\s*=\s*\?", re.I)


def _literals() -> list[tuple[Path, int, str]]:
    found = []
    for directory in STORE_DIRS:
        for path in sorted(directory.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    found.append((path, node.lineno, node.value))
                elif isinstance(node, ast.JoinedStr):
                    text = "".join(part.value if isinstance(part, ast.Constant) else "{}" for part in node.values)
                    found.append((path, node.lineno, text))
    return found


def _tenant_keyed_tables(literals) -> set[str]:
    tables = set()
    for _path, _line, text in literals:
        for name, body in CREATE.findall(text):
            key = KEYED_PK.search(body)
            if key and TENANT.search(key.group(1)):
                tables.add(name.lower())
    return tables


def test_tenant_keyed_writes_always_name_the_tenant() -> None:
    literals = _literals()
    keyed = _tenant_keyed_tables(literals)
    assert {"agent_identities", "fleet_agents"} <= keyed
    unscoped = []
    for path, line, text in literals:
        match = WRITE.match(text)
        if not match:
            continue
        table = (match.group(1) or match.group(2)).lower()
        where = re.split(r"\bWHERE\b", match.group(3), maxsplit=1, flags=re.I)[-1]
        if table not in keyed or TENANT.search(text) or "{}" in where or "%s" in text:
            continue
        ids = [
            column
            for column in ID_EQUALITY.findall(where)
            if column.lower() not in {"tenant_id", "team_id"} and (table, (column.lower(),)) not in GLOBAL_KEYS
        ]
        if ids:
            unscoped.append(f"{path.relative_to(ROOT)}:{line}: {table} by {', '.join(ids)}")
    assert unscoped == []
