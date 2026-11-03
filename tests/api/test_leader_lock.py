"""Cluster leader election for background loops that write shared state.

A fake advisory-lock server stands in for Postgres session-level advisory
locks: a lock belongs to one session, ``pg_try_advisory_lock`` never blocks,
and the server releases every lock a session holds when the session ends.
Each simulated replica gets its own ``PostgresAdvisoryLeaderLock`` and its own
connections, as separate processes would.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from typing import Any

import pytest

from agent_bom.api import advisory_rematch, leader_lock, side_scan_scheduler
from agent_bom.api.leader_lock import (
    ADVISORY_REMATCH_LEADER_LOCK_ID,
    SCHEDULER_LEADER_LOCK_ID,
    SIDE_SCAN_SCHEDULER_LEADER_LOCK_ID,
    AlwaysLeader,
    PostgresAdvisoryLeaderLock,
    cluster_leader_lock,
)


class _Cursor:
    def __init__(self, row: tuple[Any, ...]) -> None:
        self._row = row

    def fetchone(self) -> tuple[Any, ...]:
        return self._row


class FakeAdvisoryServer:
    """Session-scoped advisory locks with Postgres semantics."""

    def __init__(self) -> None:
        self.holders: dict[int, FakeSession] = {}
        self.mutex = threading.Lock()
        self.sessions: list[FakeSession] = []

    def end_session(self, session: FakeSession) -> None:
        with self.mutex:
            for lock_id in [key for key, holder in self.holders.items() if holder is session]:
                del self.holders[lock_id]


class FakeSession:
    def __init__(self, server: FakeAdvisoryServer) -> None:
        self.server = server
        self.closed = False
        server.sessions.append(self)

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> _Cursor:
        if self.closed:
            raise OSError("server closed the connection unexpectedly")
        lock_id = int(params[0]) if params else 0
        with self.server.mutex:
            holder = self.server.holders.get(lock_id)
            if "pg_try_advisory_lock" in sql:
                if holder is None:
                    self.server.holders[lock_id] = self
                return _Cursor((self.server.holders[lock_id] is self,))
            if "pg_advisory_unlock" in sql:
                if holder is self:
                    del self.server.holders[lock_id]
                return _Cursor((holder is self,))
            if "pg_locks" in sql:
                return _Cursor((holder is self,))
        raise AssertionError(f"unexpected SQL: {sql}")

    def commit(self) -> None:
        if self.closed:
            raise OSError("server closed the connection unexpectedly")

    def close(self) -> None:
        self.closed = True
        self.server.end_session(self)

    def drop(self) -> None:
        """The network or server ends the session under the client."""
        self.close()


class FakePool:
    def __init__(self, server: FakeAdvisoryServer) -> None:
        self.server = server
        self.checked_out: list[FakeSession] = []

    def getconn(self) -> FakeSession:
        session = FakeSession(self.server)
        self.checked_out.append(session)
        return session

    def putconn(self, conn: FakeSession) -> None:
        self.checked_out.remove(conn)


def _replica_lock(server: FakeAdvisoryServer) -> Callable[..., PostgresAdvisoryLeaderLock]:
    def factory(lock_id: int, name: str) -> PostgresAdvisoryLeaderLock:
        pool = FakePool(server)
        return PostgresAdvisoryLeaderLock(lock_id, name, pool_factory=lambda: pool)

    return factory


def test_lock_ids_are_distinct_per_loop() -> None:
    assert len({SCHEDULER_LEADER_LOCK_ID, ADVISORY_REMATCH_LEADER_LOCK_ID, SIDE_SCAN_SCHEDULER_LEADER_LOCK_ID}) == 3


def test_single_node_without_postgres_is_always_leader(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.setattr("agent_bom.api.postgres_common._get_pool", lambda: pytest.fail("single node must not open Postgres"))
    lock = cluster_leader_lock(SIDE_SCAN_SCHEDULER_LEADER_LOCK_ID, "side-scan scheduler")
    assert isinstance(lock, AlwaysLeader)
    assert lock.ensure() is True
    lock.release()


@pytest.mark.parametrize("variable", ["AGENT_BOM_POSTGRES_URL", "AGENT_BOM_DB"])
def test_postgres_deployment_selects_advisory_lock(monkeypatch: pytest.MonkeyPatch, variable: str) -> None:
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.setenv(variable, "postgresql://fixture.invalid/agent_bom")
    assert isinstance(cluster_leader_lock(ADVISORY_REMATCH_LEADER_LOCK_ID, "advisory re-match"), PostgresAdvisoryLeaderLock)


def test_advisory_lock_is_exclusive_and_released() -> None:
    server = FakeAdvisoryServer()
    first, second = (_replica_lock(server)(ADVISORY_REMATCH_LEADER_LOCK_ID, "rematch") for _ in range(2))
    assert first.ensure() is True
    assert second.ensure() is False
    assert first.ensure() is True, "the holder stays leader on later checks"
    first.release()
    assert server.holders == {}
    assert second.ensure() is True


def test_distinct_loops_do_not_contend() -> None:
    server = FakeAdvisoryServer()
    factory = _replica_lock(server)
    assert factory(ADVISORY_REMATCH_LEADER_LOCK_ID, "rematch").ensure() is True
    assert factory(SIDE_SCAN_SCHEDULER_LEADER_LOCK_ID, "side-scan").ensure() is True


def test_connection_loss_hands_over_and_holder_steps_down() -> None:
    server = FakeAdvisoryServer()
    first, second = (_replica_lock(server)(SIDE_SCAN_SCHEDULER_LEADER_LOCK_ID, "side-scan") for _ in range(2))
    assert first.ensure() is True
    server.holders[SIDE_SCAN_SCHEDULER_LEADER_LOCK_ID].drop()
    assert second.ensure() is True, "the server released the dead session's lock"
    assert first.ensure() is False, "the old holder notices the lost session and does not run"
    second.release()
    assert first.ensure() is True, "and re-acquires on a fresh connection once free"


def test_failed_acquire_returns_connection_and_fails_closed() -> None:
    server = FakeAdvisoryServer()

    class _BrokenPool(FakePool):
        def getconn(self) -> FakeSession:
            session = super().getconn()
            session.closed = True
            return session

    pool = _BrokenPool(server)
    lock = PostgresAdvisoryLeaderLock(SCHEDULER_LEADER_LOCK_ID, "scheduler", pool_factory=lambda: pool)
    assert lock.ensure() is False
    assert pool.checked_out == []

    unreachable = PostgresAdvisoryLeaderLock(
        SCHEDULER_LEADER_LOCK_ID, "scheduler", pool_factory=lambda: (_ for _ in ()).throw(OSError("unreachable"))
    )
    assert unreachable.ensure() is False


def test_release_returns_connection_to_pool() -> None:
    server = FakeAdvisoryServer()
    pool = FakePool(server)
    lock = PostgresAdvisoryLeaderLock(SCHEDULER_LEADER_LOCK_ID, "scheduler", pool_factory=lambda: pool)
    assert lock.ensure() is True
    lock.release()
    assert pool.checked_out == []
    assert server.holders == {}
    lock.release()


async def _run_replicas(loops: list[Callable[[], Any]], settle: float) -> list[asyncio.Task[None]]:
    tasks = [asyncio.create_task(loop()) for loop in loops]
    await asyncio.sleep(settle)
    return tasks


async def _cancel(tasks: list[asyncio.Task[None]]) -> None:
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


def _counting(counter: list[str], value: Any) -> Callable[..., Any]:
    def body(*_args: Any, **_kwargs: Any) -> Any:
        counter.append("ran")
        return value

    return body


REPLICAS = 5


def test_side_scan_scheduler_runs_on_one_replica_and_fails_over(monkeypatch: pytest.MonkeyPatch) -> None:
    server = FakeAdvisoryServer()
    monkeypatch.setattr(side_scan_scheduler, "cluster_leader_lock", _replica_lock(server))
    monkeypatch.setattr(leader_lock, "STANDBY_POLL_SECONDS", 0.01)
    passes: list[str] = []

    async def schedule() -> list[dict[str, Any]]:
        passes.append("ran")
        return []

    monkeypatch.setattr(side_scan_scheduler, "schedule_provider_side_scans", schedule)

    async def scenario() -> None:
        tasks = await _run_replicas([lambda: side_scan_scheduler.side_scan_scheduler_loop(poll_seconds=3600)] * REPLICAS, 0.2)
        assert passes == ["ran"], "exactly one replica drives the cloud side-scan pass"
        server.holders[SIDE_SCAN_SCHEDULER_LEADER_LOCK_ID].drop()
        await asyncio.sleep(0.2)
        assert passes == ["ran", "ran"], "a standby takes over once the leader's session ends"
        await _cancel(tasks)

    asyncio.run(scenario())
    assert server.holders == {}, "cancelled replicas release the lock"


def test_advisory_rematch_runs_on_one_replica(monkeypatch: pytest.MonkeyPatch) -> None:
    server = FakeAdvisoryServer()
    monkeypatch.setattr(advisory_rematch, "cluster_leader_lock", _replica_lock(server))
    monkeypatch.setattr(leader_lock, "STANDBY_POLL_SECONDS", 0.01)
    runs: list[str] = []
    monkeypatch.setattr(advisory_rematch, "run_rematch_once", _counting(runs, {"status": "complete", "tenants_examined": 0}))

    async def scenario() -> None:
        tasks = await _run_replicas([advisory_rematch.advisory_rematch_loop] * REPLICAS, 0.2)
        assert runs == ["ran"], "exactly one replica advances the shared re-match cursors"
        await _cancel(tasks)

    asyncio.run(scenario())
    assert server.holders == {}


def test_standby_replica_never_runs_rematch(monkeypatch: pytest.MonkeyPatch) -> None:
    server = FakeAdvisoryServer()
    holder = _replica_lock(server)(ADVISORY_REMATCH_LEADER_LOCK_ID, "other replica")
    assert holder.ensure() is True
    monkeypatch.setattr(advisory_rematch, "cluster_leader_lock", _replica_lock(server))
    monkeypatch.setattr(leader_lock, "STANDBY_POLL_SECONDS", 0.01)
    monkeypatch.setattr(advisory_rematch, "run_rematch_once", lambda **_: pytest.fail("standby must not run"))

    async def scenario() -> None:
        tasks = await _run_replicas([advisory_rematch.advisory_rematch_loop], 0.05)
        await _cancel(tasks)

    asyncio.run(scenario())
    holder.release()
    assert server.holders == {}


@pytest.mark.parametrize("module", [side_scan_scheduler, advisory_rematch])
def test_single_node_sqlite_loop_still_runs(monkeypatch: pytest.MonkeyPatch, module: Any) -> None:
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.setenv("AGENT_BOM_DB", "sqlite:///tmp/agent-bom-leader.db")
    monkeypatch.setattr("agent_bom.api.postgres_common._get_pool", lambda: pytest.fail("single node must not open Postgres"))
    runs: list[str] = []
    if module is side_scan_scheduler:

        async def schedule() -> list[dict[str, Any]]:
            runs.append("ran")
            return []

        monkeypatch.setattr(module, "schedule_provider_side_scans", schedule)
        loop: Callable[[], Any] = lambda: module.side_scan_scheduler_loop(poll_seconds=3600)  # noqa: E731
    else:
        monkeypatch.setattr(module, "run_rematch_once", _counting(runs, {"status": "complete", "tenants_examined": 0}))
        loop = module.advisory_rematch_loop

    async def scenario() -> None:
        tasks = await _run_replicas([loop], 0.05)
        await _cancel(tasks)

    asyncio.run(scenario())
    assert runs == ["ran"]


def test_scan_scheduler_gates_on_db_alias_and_survives_connection_loss(monkeypatch: pytest.MonkeyPatch) -> None:
    from contextlib import nullcontext

    from agent_bom.api import scheduler, tenant_quota
    from agent_bom.api.schedule_store import InMemoryScheduleStore, ScanSchedule

    class PostgresScheduleStore(InMemoryScheduleStore):
        pass

    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.setenv("AGENT_BOM_DB", "postgresql://fixture.invalid/agent_bom")
    monkeypatch.setattr(tenant_quota, "_maybe_postgres_advisory_lock", lambda _tenant_id: nullcontext())
    server = FakeAdvisoryServer()
    pool = FakePool(server)
    monkeypatch.setattr("agent_bom.api.postgres_common._get_pool", lambda: pool)
    store = PostgresScheduleStore()
    due = "2020-01-01T00:00:00+00:00"
    store.put(
        ScanSchedule(
            schedule_id="s1",
            name="nightly",
            cron_expression="0 */6 * * *",
            scan_config={"images": ["nginx:latest"]},
            enabled=True,
            next_run=due,
            created_at=due,
            updated_at=due,
            tenant_id="default",
        ),
        tenant_id="default",
    )
    triggered: list[str] = []

    def run_scan(_config: dict[str, Any], **_metadata: Any) -> str:
        triggered.append("scan")
        return f"job-{len(triggered)}"

    async def scenario() -> None:
        tasks = await _run_replicas([lambda: scheduler.scheduler_loop(store, run_scan, interval_seconds=0)] * REPLICAS, 0.2)
        assert triggered == ["scan"], "only the leader dispatches the due schedule"
        server.holders[SCHEDULER_LEADER_LOCK_ID].drop()
        current = store.get("s1", tenant_id="default")
        assert current is not None
        current.next_run = due
        store.put(current, tenant_id="default")
        await asyncio.sleep(0.2)
        assert triggered == ["scan", "scan"], "a replica re-acquires after the leader's session is lost"
        await _cancel(tasks)

    asyncio.run(scenario())
    assert server.holders == {}


def test_process_local_cache_warmers_stay_ungated() -> None:
    """Each replica warms its own memory; gating these would leave the others cold."""
    import inspect

    from agent_bom.api import exec_read_prewarm, posture_counts_cache

    for module in (posture_counts_cache, exec_read_prewarm):
        source = inspect.getsource(module)
        assert "leader_lock" not in source
        assert "Not leader-gated" in source or "not leader-gated" in source


def test_cleanup_failure_never_escapes_ensure() -> None:
    server = FakeAdvisoryServer()

    class _Session(FakeSession):
        def execute(self, sql: str, params: tuple[Any, ...] = ()) -> _Cursor:
            raise OSError("connection reset")

        def close(self) -> None:
            raise OSError("already closed")

    class _Pool(FakePool):
        def getconn(self) -> FakeSession:
            return _Session(self.server)

        def putconn(self, conn: FakeSession) -> None:
            raise ValueError("connection not from this pool")

    pool = _Pool(server)
    assert PostgresAdvisoryLeaderLock(SCHEDULER_LEADER_LOCK_ID, "scheduler", pool_factory=lambda: pool).ensure() is False
