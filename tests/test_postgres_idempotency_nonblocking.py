"""Real-Postgres contract: a claim never waits on another replica's committing row lock."""

from __future__ import annotations

import os
import threading
import time
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="AGENT_BOM_POSTGRES_URL is required for real Postgres integration tests",
)


@pytest.fixture(autouse=True)
def _reset_pool():
    from agent_bom.api import postgres_common

    postgres_common.reset_pool()
    yield
    postgres_common.reset_pool()


def test_postgres_claim_returns_in_flight_while_another_replica_commits(monkeypatch) -> None:
    from agent_bom.api.idempotency_store import PostgresIdempotencyStore, idempotency_request_fingerprint
    from agent_bom.api.postgres_common import _new_application_pool

    monkeypatch.setenv("AGENT_BOM_IDEMPOTENCY_RESERVATION_LEASE_SECONDS", "1")
    pools = [_new_application_pool(min_size=1, max_size=1) for _ in range(4)]
    try:
        replica_a = PostgresIdempotencyStore(pool=pools[0], fence_pool=pools[1])
        replica_b = PostgresIdempotencyStore(pool=pools[2], fence_pool=pools[3])
        suffix = uuid4().hex
        args = ("/v1/results/push", "default", f"source-{suffix}", f"key-{suffix}")
        request_hash = idempotency_request_fingerprint({"value": suffix})
        _receipt, acquired = replica_a.claim(
            *args, {"job_id": f"job-{suffix}", "committed": False}, request_hash=request_hash, reservation_lease_seconds=1, owner_token="a"
        )
        assert acquired is True
        started, release = threading.Event(), threading.Event()
        outcome: dict[str, object] = {}

        def _action() -> str:
            started.set()
            assert release.wait(15)
            return "a"

        def _owner() -> None:
            try:
                outcome["owner"] = replica_a.commit_claim(
                    *args, {"job_id": f"job-{suffix}", "committed": True}, action=_action, request_hash=request_hash, owner_token="a"
                )
            except Exception as exc:  # noqa: BLE001 - surfaced through the assertion below
                outcome["owner"] = type(exc).__name__

        owner = threading.Thread(target=_owner)
        owner.start()
        try:
            assert started.wait(5)
            time.sleep(1.2)  # the lease is now expired while the row lock is live
            began = time.monotonic()
            receipt, rival = replica_b.claim(
                *args,
                {"job_id": f"job-{suffix}", "committed": False},
                request_hash=request_hash,
                reservation_lease_seconds=1,
                owner_token="b",
            )
            elapsed = time.monotonic() - began
            other_args = ("/v1/results/push", "default", f"source-{suffix}", f"other-{suffix}")
            began = time.monotonic()
            _receipt, other = replica_b.claim(
                *other_args,
                {"job_id": "other", "committed": False},
                request_hash=request_hash,
                reservation_lease_seconds=30,
                owner_token="c",
            )
            other_elapsed = time.monotonic() - began
        finally:
            release.set()
            owner.join(15)
        assert elapsed < 1.0, elapsed
        assert other_elapsed < 1.0, other_elapsed
        assert rival is False
        assert receipt["job_id"] == f"job-{suffix}"
        assert other is True
        assert outcome == {"owner": "a"}
        assert replica_b.get(*args, request_hash=request_hash) == {"job_id": f"job-{suffix}", "committed": True}
    finally:
        for pool in pools:
            pool.close()
