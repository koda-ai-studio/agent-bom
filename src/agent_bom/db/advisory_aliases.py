"""Transactionally maintained reverse aliases for the local vulnerability feed.

An indexed read visits only records naming the requested alias. Keeping this
projection in SQLite avoids a process-sized alias map and TTL-based staleness.
The source ``vulns.aliases`` remains authoritative; the v9 migration backfills
existing rows and triggers track every subsequent write, including replacement.
"""

from __future__ import annotations

import sqlite3

ALIAS_SCHEMA = """
CREATE TABLE IF NOT EXISTS vuln_aliases (
    vuln_id TEXT NOT NULL,
    alias_id TEXT NOT NULL,
    PRIMARY KEY (vuln_id, alias_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_vuln_alias_lookup ON vuln_aliases(alias_id, vuln_id);

CREATE TRIGGER IF NOT EXISTS vuln_alias_insert AFTER INSERT ON vulns
WHEN coalesce(NEW.aliases, '') != '' OR EXISTS (SELECT 1 FROM vuln_aliases WHERE vuln_id = NEW.id) BEGIN
    DELETE FROM vuln_aliases WHERE vuln_id = NEW.id;
    INSERT OR IGNORE INTO vuln_aliases(vuln_id, alias_id)
        SELECT NEW.id, upper(value)
        FROM json_each('[' || replace(json_quote(coalesce(NEW.aliases, '')), ',', '","') || ']')
        WHERE value != '';
END;
CREATE TRIGGER IF NOT EXISTS vuln_alias_update AFTER UPDATE OF id, aliases ON vulns
WHEN OLD.id IS NOT NEW.id OR OLD.aliases IS NOT NEW.aliases BEGIN
    DELETE FROM vuln_aliases WHERE vuln_id IN (OLD.id, NEW.id);
    INSERT OR IGNORE INTO vuln_aliases(vuln_id, alias_id)
        SELECT NEW.id, upper(value)
        FROM json_each('[' || replace(json_quote(coalesce(NEW.aliases, '')), ',', '","') || ']')
        WHERE value != '';
END;
CREATE TRIGGER IF NOT EXISTS vuln_alias_delete AFTER DELETE ON vulns BEGIN
    DELETE FROM vuln_aliases WHERE vuln_id = OLD.id;
END;
"""

# json_quote escapes quotes/backslashes before comma splitting, so feed strings
# remain data. Do not trim tokens: the legacy comma-delimited query did not.
ALIAS_BACKFILL = """
INSERT OR IGNORE INTO vuln_aliases(vuln_id, alias_id)
    SELECT v.id, upper(a.value)
    FROM vulns AS v,
         json_each('[' || replace(json_quote(coalesce(v.aliases, '')), ',', '","') || ']') AS a
    WHERE a.value != '';
"""


def alias_index_ready(conn: sqlite3.Connection) -> bool:
    """Only use a completed index; read-only legacy databases keep their scan path.

    DDL can precede migration backfill. The schema version advances in the
    backfill transaction, so a concurrent reader never trusts a partial index.
    """
    tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('schema_version', 'vuln_aliases')").fetchall()
    if len(tables) != 2:
        return False
    version = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
    return version is not None and int(version[0]) >= 9
