"""Bounded cleanup-tick backfill for current findings an older writer left pending.

Alembic materializes existing rows during the upgrade. This tick finishes rows
written by replicas that were still draining, and any budget the migration ran
out of. Batches are small and committed separately, and Postgres skips rows a
writer holds, so ingest and reads are not blocked and replicas can run it at once.
"""

from __future__ import annotations

import time

from agent_bom.api import compliance_hub_store

_BATCH_ROWS = 500
_TICK_BUDGET_SECONDS = 5.0


def run_materialization_tick(*, budget_seconds: float = _TICK_BUDGET_SECONDS, batch_rows: int = _BATCH_ROWS) -> int:
    """Materialize pending rows until none remain or the budget ends; returns rows handled."""
    backfill = getattr(compliance_hub_store.get_compliance_hub_store(), "backfill_materialized_batch", None)
    if not callable(backfill):
        return 0
    deadline = time.monotonic() + budget_seconds
    total = 0
    while time.monotonic() < deadline:
        done = int(backfill(batch_rows))
        total += done
        if not done:
            break
    return total
