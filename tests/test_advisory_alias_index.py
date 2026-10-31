"""Alias reads stay bounded and transactionally current as feeds change."""

from __future__ import annotations

import sqlite3

import pytest

from agent_bom.db.schema import init_db, open_existing_db_readonly
from agent_bom.scanners.advisory_affected import _alias_records


def _put(conn, identifier, aliases):
    conn.execute(
        "INSERT OR REPLACE INTO vulns (id, summary, severity, aliases, source) VALUES (?, 'summary', 'high', ?, 'osv')",
        (identifier, aliases),
    )


def _ids(conn, alias):
    return [row[0] for row in _alias_records(conn, alias)]


def test_alias_read_does_not_walk_unrelated_feed_rows(tmp_path):
    path = tmp_path / "vulns.db"
    conn = init_db(path)
    conn.executemany(
        "INSERT INTO vulns (id, summary, severity, aliases, source) VALUES (?, 'summary', 'high', ?, 'osv')",
        [(f"OSV-unrelated-{i:05d}", f"CVE-2025-{i + 10000}") for i in range(5000)],
    )
    _put(conn, "GHSA-target", "CVE-2026-7000")
    conn.commit()
    conn.close()
    with open_existing_db_readonly(path) as reader:
        calls = 0

        def budget():
            nonlocal calls
            calls += 1
            return calls > 15

        reader.set_progress_handler(budget, 1000)
        try:
            assert _ids(reader, "CVE-2026-7000") == ["GHSA-target"]
        except sqlite3.OperationalError as exc:
            assert str(exc) != "interrupted", "Alias lookup exhausted 15,000 VM instructions walking unrelated feed rows"
            raise
        finally:
            reader.set_progress_handler(None, 0)


@pytest.mark.parametrize("foreign_keys", [True, False])
def test_alias_index_tracks_insert_replace_update_delete_and_rollback(tmp_path, foreign_keys):
    path = tmp_path / "vulns.db"
    writer = init_db(path)
    writer.execute(f"PRAGMA foreign_keys = {int(foreign_keys)}")
    reader = open_existing_db_readonly(path)
    try:
        _put(writer, "GHSA-target", "CVE-2026-7000,CVE-2026-7000,,")
        writer.commit()
        assert _ids(reader, "CVE-2026-7000") == ["GHSA-target"]
        _put(writer, "GHSA-target", "CVE-2026-7001")
        assert _ids(reader, "CVE-2026-7000") == ["GHSA-target"]  # uncommitted writer is invisible
        writer.commit()
        assert _ids(reader, "CVE-2026-7000") == []
        assert _ids(reader, "CVE-2026-7001") == ["GHSA-target"]
        writer.execute("UPDATE vulns SET id='GHSA-renamed', aliases='cve-2026-7002' WHERE id='GHSA-target'")
        writer.commit()
        assert _ids(reader, "CVE-2026-7001") == []
        assert _ids(reader, "CVE-2026-7002") == ["GHSA-renamed"]
        writer.execute("UPDATE vulns SET aliases='CVE-2026-7003' WHERE id='GHSA-renamed'")
        writer.rollback()
        assert _ids(reader, "CVE-2026-7002") == ["GHSA-renamed"]
        assert _ids(reader, "CVE-2026-7003") == []
        _put(writer, "GHSA-renamed", "")
        writer.commit()
        assert _ids(reader, "CVE-2026-7002") == []
        _put(writer, "GHSA-renamed", "CVE-2026-7002")
        writer.commit()
        writer.execute("DELETE FROM vulns WHERE id='GHSA-renamed'")
        writer.commit()
        assert _ids(reader, "CVE-2026-7002") == []
        assert writer.execute("SELECT count(*) FROM vuln_aliases").fetchone()[0] == 0
    finally:
        writer.close()
        reader.close()


def _legacy(path):
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version VALUES (8);
        CREATE TABLE vulns (
            id TEXT PRIMARY KEY, summary TEXT, severity TEXT, aliases TEXT,
            published TEXT, cvss_score REAL, cvss_vector TEXT, source TEXT
        );
    """)
    _put(conn, "GHSA-target", "CVE-2026-7000")
    conn.commit()
    conn.close()


def test_legacy_readonly_database_stays_readable_and_migration_backfills(tmp_path):
    path = tmp_path / "legacy.db"
    _legacy(path)
    with open_existing_db_readonly(path) as reader:
        assert _ids(reader, "CVE-2026-7000") == ["GHSA-target"]
        assert reader.execute("SELECT version FROM schema_version").fetchone()[0] == 8
    migrated = init_db(path)
    try:
        assert migrated.execute("SELECT version FROM schema_version").fetchone()[0] == 9
        assert _ids(migrated, "CVE-2026-7000") == ["GHSA-target"]
        assert [tuple(row) for row in migrated.execute("SELECT vuln_id, alias_id FROM vuln_aliases")] == [("GHSA-target", "CVE-2026-7000")]
    finally:
        migrated.close()
    with init_db(path) as reopened:
        assert _ids(reopened, "CVE-2026-7000") == ["GHSA-target"]
        assert reopened.execute("SELECT count(*) FROM vuln_aliases").fetchone()[0] == 1


def test_alias_index_preserves_exact_tokens_case_order_and_limit(tmp_path):
    with init_db(tmp_path / "vulns.db") as conn:
        for i in reversed(range(40)):
            _put(conn, f"OSV-{i:02d}", "cve-2026-7000")
        _put(conn, "OSV-prefix", "CVE-2026-70001")
        _put(conn, "OSV-suffix", "X-CVE-2026-7000")
        _put(conn, "OSV-quotes", 'quote"value,back\\slash,CVE-2026-7001')
        _put(conn, "OSV-null", None)
        assert _ids(conn, "CVE-2026-7000") == [f"OSV-{i:02d}" for i in range(32)]
        assert _ids(conn, "CVE-2026-7001") == ["OSV-quotes"]


def test_failed_backfill_is_not_used_and_retry_restores_the_index(tmp_path, monkeypatch):
    from agent_bom.db import schema

    path = tmp_path / "retry.db"
    _legacy(path)
    migrations = schema._MIGRATIONS
    with monkeypatch.context() as patch:
        patch.setattr(schema, "_MIGRATIONS", [*migrations[:-1], (8, 9, migrations[-1][2] + " SELECT missing_column FROM vulns;")])
        with pytest.raises(sqlite3.OperationalError, match="missing_column"):
            init_db(path)
    with open_existing_db_readonly(path) as reader:
        assert reader.execute("SELECT version FROM schema_version").fetchone()[0] == 8
        assert reader.execute("SELECT count(*) FROM vuln_aliases").fetchone()[0] == 0
        assert _ids(reader, "CVE-2026-7000") == ["GHSA-target"]
    with init_db(path) as retry:
        assert retry.execute("SELECT version FROM schema_version").fetchone()[0] == 9
        assert _ids(retry, "CVE-2026-7000") == ["GHSA-target"]
