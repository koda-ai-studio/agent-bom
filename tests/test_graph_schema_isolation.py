"""Cold graph stores and failed probes do not serialize unrelated databases."""

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from agent_bom.db.graph_bootstrap import ensure_read_schema, invalidate_read_schema


@pytest.mark.parametrize("operation", ["initialize", "invalidate"])
def test_blocked_initialization_does_not_block_another_database(tmp_path, operation):
    first, other = (tmp_path / name for name in ("first.db", "other.db"))
    for path in (first, other):
        sqlite3.connect(path).close()
    entered, release = Event(), Event()

    def blocked_initialize():
        entered.set()
        assert release.wait(5)
        return sqlite3.connect(first)

    def independent_operation():
        if operation == "initialize":
            ensure_read_schema(other, lambda: sqlite3.connect(other), lambda conn: None)
        else:
            invalidate_read_schema(other)
        return True

    with ThreadPoolExecutor(max_workers=2) as workers:
        blocked = workers.submit(ensure_read_schema, first, blocked_initialize, lambda conn: None)
        assert entered.wait(5)
        independent = workers.submit(independent_operation)
        try:
            assert independent.result(timeout=1)
        finally:
            release.set()
        blocked.result(timeout=5)


def test_a_recreated_file_on_a_reused_inode_gets_its_schema_again(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    db = tmp_path / "projection.db"
    store = SQLiteGraphStore(db)
    store.check_readiness()
    assert store.snapshot_identity(tenant_id="t", for_paging=True)[0] == ""

    # Same device and inode with no content is what a sweep and re-create leave when Linux reuses the inode.
    os.truncate(db, 0)
    for sidecar in (tmp_path / "projection.db-wal", tmp_path / "projection.db-shm"):
        sidecar.unlink(missing_ok=True)

    assert store.snapshot_identity(tenant_id="t", for_paging=True)[0] == ""
