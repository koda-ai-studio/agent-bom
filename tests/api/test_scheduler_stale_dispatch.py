"""A due-list read must not authorize dispatch after leadership or state changes."""

import asyncio
from contextlib import nullcontext

import pytest

from agent_bom.api import scheduler, tenant_quota
from agent_bom.api.schedule_store import InMemoryScheduleStore, ScanSchedule


@pytest.mark.parametrize("change", ["lost_leadership", "advanced", "disabled", "deleted"])
def test_due_read_cannot_dispatch_stale_schedule(monkeypatch, change):
    due = "2020-01-01T00:00:00+00:00"
    dispatched = []

    class Lock:
        checks = 0
        released = False

        def ensure(self):
            self.checks += 1
            if self.checks >= 3:
                raise asyncio.CancelledError
            return change != "lost_leadership" or self.checks == 1

        def release(self):
            self.released = True

    class PostgresScheduleStore(InMemoryScheduleStore):
        def list_due(self, now):
            rows = super().list_due(now)
            # A successor or operator changes the durable record while a read
            # is in flight. Return the previously collected due-list snapshot.
            current = self.get("s1", tenant_id="fixture")
            if change == "advanced":
                current.next_run = "2099-01-01T00:00:00+00:00"
            elif change == "disabled":
                current.enabled = False
            self.put(current, tenant_id="fixture")
            if change == "deleted":
                self.delete("s1", tenant_id="fixture")
            return rows

    store = PostgresScheduleStore()
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
            tenant_id="fixture",
        ),
        tenant_id="fixture",
    )
    lock = Lock()
    monkeypatch.setattr(scheduler, "cluster_leader_lock", lambda *_: lock)
    monkeypatch.setattr(tenant_quota, "_maybe_postgres_advisory_lock", lambda _: nullcontext())

    def run_scan(config, **metadata):
        dispatched.append(metadata)
        return "fixture-job"

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(scheduler.scheduler_loop(store, run_scan, interval_seconds=0))
    assert dispatched == []
    assert lock.released
