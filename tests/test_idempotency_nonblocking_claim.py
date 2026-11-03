"""A claim must never wait behind another request's durable commit action."""

from __future__ import annotations

import threading
import time

from agent_bom.api.idempotency_store import SQLiteIdempotencyStore, idempotency_request_fingerprint

_ENDPOINT = "/v1/results/push"


def _same_stripe_key(store: SQLiteIdempotencyStore, tenant: str, source: str, key: str) -> str:
    stripe = store._claim_lock_digest(_ENDPOINT, tenant, source, key)[:2]
    for index in range(10_000):
        candidate = f"other-{index}"
        if store._claim_lock_digest(_ENDPOINT, tenant, source, candidate)[:2] == stripe:
            return candidate
    raise AssertionError("no colliding stripe key found")


def test_sqlite_claim_never_blocks_behind_a_live_commit(tmp_path) -> None:
    """An in-flight retry and an unrelated key on the same lock stripe both answer immediately."""

    db_path = str(tmp_path / "nonblocking.db")
    owner_store = SQLiteIdempotencyStore(db_path)
    request_hash = idempotency_request_fingerprint({"value": 1})
    args = (_ENDPOINT, "tenant-a", "source-a", "slow-key")
    _receipt, acquired = owner_store.claim(
        *args, {"job_id": "slow-job", "committed": False}, request_hash=request_hash, reservation_lease_seconds=1, owner_token="owner-a"
    )
    assert acquired is True
    started = threading.Event()
    release = threading.Event()

    def _slow_action() -> str:
        started.set()
        assert release.wait(10)
        return "done"

    owner = threading.Thread(
        target=lambda: owner_store.commit_claim(
            *args, {"job_id": "slow-job", "committed": True}, action=_slow_action, request_hash=request_hash, owner_token="owner-a"
        )
    )
    owner.start()
    try:
        assert started.wait(5)
        # The reservation lease lapses while the durable action is still live:
        # the rival must neither wait nor take the key over.
        time.sleep(1.2)
        rival_store = SQLiteIdempotencyStore(db_path)
        began = time.monotonic()
        receipt, rival_acquired = rival_store.claim(
            *args, {"job_id": "slow-job", "committed": False}, request_hash=request_hash, reservation_lease_seconds=1, owner_token="owner-b"
        )
        assert time.monotonic() - began < 0.5
        assert rival_acquired is False
        assert receipt == {"job_id": "slow-job", "committed": False}

        neighbour = _same_stripe_key(rival_store, "tenant-a", "source-a", "slow-key")
        began = time.monotonic()
        _receipt, neighbour_acquired = rival_store.claim(
            _ENDPOINT,
            "tenant-a",
            "source-a",
            neighbour,
            {"job_id": "other", "committed": False},
            request_hash=request_hash,
            reservation_lease_seconds=30,
            owner_token="owner-c",
        )
        assert time.monotonic() - began < 0.5
        assert neighbour_acquired is True
    finally:
        release.set()
        owner.join(10)
    assert not owner.is_alive()
    assert owner_store.get(*args, request_hash=request_hash) == {"job_id": "slow-job", "committed": True}


def test_sqlite_claim_still_reclaims_an_abandoned_reservation_when_unfenced(tmp_path) -> None:
    """Non-blocking fencing must not strand keys whose owner died without a live commit."""

    db_path = str(tmp_path / "reclaim.db")
    store = SQLiteIdempotencyStore(db_path)
    request_hash = idempotency_request_fingerprint({"value": 2})
    args = (_ENDPOINT, "tenant-a", "source-a", "abandoned")
    assert store.claim(
        *args, {"job_id": "j", "committed": False}, request_hash=request_hash, reservation_lease_seconds=1, owner_token="dead"
    )[1]
    time.sleep(1.2)
    _receipt, acquired = store.claim(
        *args, {"job_id": "j", "committed": False}, request_hash=request_hash, reservation_lease_seconds=1, owner_token="alive"
    )
    assert acquired is True


def test_in_memory_claim_never_blocks_behind_a_live_commit() -> None:
    from agent_bom.api.idempotency_store import InMemoryIdempotencyStore

    store = InMemoryIdempotencyStore()
    request_hash = idempotency_request_fingerprint({"value": 3})
    args = (_ENDPOINT, "tenant-a", "source-a", "slow")
    assert store.claim(*args, {"job_id": "j", "committed": False}, request_hash=request_hash, reservation_lease_seconds=1, owner_token="a")[
        1
    ]
    started, release = threading.Event(), threading.Event()

    def _action() -> str:
        started.set()
        assert release.wait(10)
        return "ok"

    owner = threading.Thread(
        target=lambda: store.commit_claim(
            *args, {"job_id": "j", "committed": True}, action=_action, request_hash=request_hash, owner_token="a"
        )
    )
    owner.start()
    try:
        assert started.wait(5)
        time.sleep(1.2)
        began = time.monotonic()
        _receipt, same = store.claim(
            *args, {"job_id": "j", "committed": False}, request_hash=request_hash, reservation_lease_seconds=1, owner_token="b"
        )
        _receipt, other = store.claim(
            _ENDPOINT, "tenant-a", "source-a", "other", {"job_id": "k", "committed": False}, request_hash=request_hash, owner_token="c"
        )
        assert time.monotonic() - began < 0.5
        assert (same, other) == (False, True)
    finally:
        release.set()
        owner.join(10)
    assert store.get(*args, request_hash=request_hash) == {"job_id": "j", "committed": True}
