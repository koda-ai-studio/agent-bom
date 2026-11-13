"""A local vulnerability DB written by one test is never visible to the next.

The default DB is ``<state dir>/db/vulns.db`` and the state dir is shared by
every test on a worker. A stale DB left there turns every later ``check`` on
that worker incomplete ("local vulnerability data is N days old"). Both cases
below first assert that no DB is present, then leave a stale one behind, so
whichever runs second proves the first one's DB was removed.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agent_bom.db import schema
from tests._vuln_db_isolation import shared_vuln_db_dirs


def _write_stale_db(path: Path) -> None:
    conn = schema.init_db(path)
    try:
        conn.execute(
            "INSERT INTO sync_meta(source,last_synced,record_count,metadata_json) VALUES (?,?,?,?)",
            ("osv", "2020-01-01T00:00:00+00:00", 1, "{}"),
        )
        conn.commit()
    finally:
        conn.close()


@pytest.mark.parametrize("case", ["first", "second"])
def test_a_stale_default_db_does_not_reach_the_next_test(case: str) -> None:
    del case
    for directory in shared_vuln_db_dirs():
        assert not (directory / "vulns.db").exists(), f"a vuln DB from an earlier test is still at {directory}"
    assert not schema.DB_PATH.exists(), f"a vuln DB from an earlier test is still at {schema.DB_PATH}"

    _write_stale_db(schema.DB_PATH)
    assert sqlite3.connect(schema.DB_PATH).execute("SELECT count(*) FROM sync_meta").fetchone()[0] == 1


def test_the_shared_default_db_is_the_one_every_reader_resolves() -> None:
    assert schema.DB_PATH.parent in shared_vuln_db_dirs()
