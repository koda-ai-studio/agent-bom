"""Leader election against a live Postgres: two sessions, one leader.

Runs in the "Run real Postgres storage contract" CI step; skips without
``AGENT_BOM_POSTGRES_URL``.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any

import pytest

from agent_bom.api.leader_lock import PostgresAdvisoryLeaderLock

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="AGENT_BOM_POSTGRES_URL is required")

# Test-only key, distinct from every production loop's lock id.
LOCK_ID = 4_197_042_901


@pytest.fixture
def pool() -> Iterator[Any]:
    from agent_bom.api.postgres_common import _new_application_pool

    created = _new_application_pool(min_size=1, max_size=4)
    try:
        yield created
    finally:
        created.close()


def _lock(pool: Any, name: str) -> PostgresAdvisoryLeaderLock:
    return PostgresAdvisoryLeaderLock(LOCK_ID, name, pool_factory=lambda: pool)


def test_pg_try_advisory_lock_is_exclusive_across_sessions(pool: Any) -> None:
    with pool.connection() as first, pool.connection() as second:
        assert first.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_ID,)).fetchone()[0] is True
        assert second.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_ID,)).fetchone()[0] is False
        assert first.execute("SELECT pg_advisory_unlock(%s)", (LOCK_ID,)).fetchone()[0] is True
        assert second.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_ID,)).fetchone()[0] is True
        assert second.execute("SELECT pg_advisory_unlock(%s)", (LOCK_ID,)).fetchone()[0] is True


def test_one_leader_handover_on_release_and_on_session_loss(pool: Any) -> None:
    first, second = _lock(pool, "replica-a"), _lock(pool, "replica-b")
    try:
        assert first.ensure() is True
        assert second.ensure() is False
        assert first.ensure() is True, "the holder's pg_locks check sees its own lock"

        first.release()
        assert second.ensure() is True
        assert first.ensure() is False

        leader_pid = second._conn.execute("SELECT pg_backend_pid()").fetchone()[0]
        second._conn.commit()
        with pool.connection() as admin:
            assert admin.execute("SELECT pg_terminate_backend(%s)", (leader_pid,)).fetchone()[0] is True
        assert first.ensure() is True, "the server released the terminated session's lock"
        assert second.ensure() is False, "the old holder detects its lost session and stands by"
    finally:
        first.release()
        second.release()
    with pool.connection() as check:
        held = check.execute("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = %s", (LOCK_ID,)).fetchone()[0]
    assert held == 0
