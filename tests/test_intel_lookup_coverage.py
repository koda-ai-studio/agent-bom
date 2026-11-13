"""An advisory miss must say whether the local database was ever synced.

A fresh install or container has an empty database, and "not found" there is
not evidence that an advisory does not exist.
"""

from __future__ import annotations

from agent_bom.db.schema import init_db
from agent_bom.intel_lookup import lookup_advisory


def test_miss_on_empty_database_is_flagged_unsynced(tmp_path):
    db = tmp_path / "vulns.db"
    init_db(db).close()
    result = lookup_advisory("CVE-2024-3651", db_path=db)
    assert result["found"] is False
    assert result["database"]["synced"] is False
    assert result["database"]["sources"] == []
    assert "not been synced" in result["database"]["note"]


def test_miss_on_synced_database_reports_sources_and_time(tmp_path):
    db = tmp_path / "vulns.db"
    conn = init_db(db)
    conn.execute(
        "INSERT INTO sync_meta (source, last_synced, record_count) VALUES (?, ?, ?)",
        ("osv", "2026-11-12T00:00:00+00:00", 42),
    )
    conn.execute("INSERT INTO sync_meta (source, last_synced, record_count) VALUES (?, ?, ?)", ("kev", "2026-11-11T00:00:00+00:00", 0))
    conn.commit()
    conn.close()
    result = lookup_advisory("CVE-0000-0000", db_path=db)
    assert result["found"] is False
    assert result["database"] == {
        "synced": True,
        "sources": ["osv"],
        "last_synced": "2026-11-12T00:00:00+00:00",
        "searched": ["osv"],
        "note": "No record of CVE-0000-0000 in OSV.",
    }
