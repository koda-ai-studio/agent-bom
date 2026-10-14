"""Give Postgres ``attack_paths`` rows route-occurrence identity.

The legacy primary key (source_node, target_node, scan_id, tenant_id) let a
second route between the same endpoints overwrite the first on upsert. Rows are
now keyed by :func:`agent_bom.graph.snapshot_paths.occurrence_path_keys`, the
same key the snapshot path index uses, and carry their ``finding_ids``.

Shared by the Alembic migration and the development bootstrap; both call these
with a psycopg connection. Every step is idempotent.
"""

from __future__ import annotations

import json
from typing import Any

from agent_bom.graph.container import AttackPath
from agent_bom.graph.snapshot_paths import occurrence_path_keys

ADD_IDENTITY_COLUMNS = (
    "ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS finding_ids TEXT DEFAULT '[]'",
    "ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS path_key TEXT NOT NULL DEFAULT ''",
)

_SWAP_PRIMARY_KEY = """
DO $$
DECLARE pk_name TEXT;
BEGIN
    SELECT c.conname INTO pk_name
    FROM pg_constraint c
    WHERE c.conrelid = to_regclass('attack_paths') AND c.contype = 'p';
    IF pk_name IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_constraint c
        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
        WHERE c.conrelid = to_regclass('attack_paths') AND c.contype = 'p' AND a.attname = 'path_key'
    ) THEN
        EXECUTE format('ALTER TABLE attack_paths DROP CONSTRAINT %I', pk_name);
        pk_name := NULL;
    END IF;
    IF pk_name IS NULL THEN
        ALTER TABLE attack_paths ADD CONSTRAINT attack_paths_pkey PRIMARY KEY (tenant_id, scan_id, path_key);
    END IF;
    ALTER TABLE attack_paths ALTER COLUMN path_key DROP DEFAULT;
END
$$
"""


def _json_list(raw: Any) -> list[Any]:
    if isinstance(raw, list):  # JSONB columns (init.sql) arrive decoded
        return raw
    try:
        value = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    return value if isinstance(value, list) else []


def backfill_attack_path_keys(conn: Any) -> int:
    """Compute keys for rows written before identity existed (``path_key = ''``)."""
    rows = conn.execute(
        "SELECT tenant_id, scan_id, source_node, target_node, path_nodes, path_edges FROM attack_paths "
        "WHERE path_key = '' ORDER BY tenant_id, scan_id, source_node, target_node"
    ).fetchall()
    scopes: dict[tuple[str, str], list[tuple[Any, ...]]] = {}
    for row in rows:
        scopes.setdefault((row[0], row[1]), []).append(tuple(row))
    updates: list[tuple[str, str, str, str, str]] = []
    for scoped in scopes.values():
        paths = (AttackPath(source=row[2], target=row[3], hops=_json_list(row[4]), edges=_json_list(row[5])) for row in scoped)
        updates.extend((key, row[0], row[1], row[2], row[3]) for row, (key, _) in zip(scoped, occurrence_path_keys(paths)))
    if updates:
        with conn.cursor() as cur:
            cur.executemany(
                "UPDATE attack_paths SET path_key = %s WHERE tenant_id = %s AND scan_id = %s AND source_node = %s "
                "AND target_node = %s AND path_key = ''",
                updates,
            )
    return len(updates)


def ensure_attack_path_identity_key(conn: Any) -> None:
    """Key the table by (tenant_id, scan_id, path_key); keys must be backfilled first."""
    conn.execute(_SWAP_PRIMARY_KEY)


def upgrade_attack_path_identity(conn: Any) -> int:
    """Add the columns, backfill keys for rows visible to *conn*, then swap the key."""
    if conn.execute("SELECT to_regclass('attack_paths')").fetchone()[0] is None:
        return 0  # queue-only legacy schemas have no graph tables yet
    for statement in ADD_IDENTITY_COLUMNS:
        conn.execute(statement)
    backfilled = backfill_attack_path_keys(conn)
    ensure_attack_path_identity_key(conn)
    return backfilled
