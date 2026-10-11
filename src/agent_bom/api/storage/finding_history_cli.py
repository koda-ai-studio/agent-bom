"""Backfill retained history without loading all reports or changing source jobs.

python -m agent_bom.api.storage.finding_history_cli --tenant TENANT
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from agent_bom.api.models import JobStatus
from agent_bom.api.storage.finding_history import KEY_BATCH
from agent_bom.core.tenancy import require_explicit_tenant_id


def backfill_tenant_history(store: Any, tenant_id: str) -> int:
    require_explicit_tenant_id(tenant_id)
    if not callable(getattr(store, "finding_history_read", None)):
        raise ValueError("finding history requires a SQLite or PostgreSQL job store")
    after: str | None = None
    count = 0
    while True:
        with store.finding_history_read(tenant_id) as reader:
            table, tenant = ("scan_jobs", "team_id") if reader.dialect == "postgres" else ("jobs", "tenant_id")
            cursor_sql = " AND job_id>?" if after is not None else ""
            params = (tenant_id, JobStatus.DONE.value, *([after] if after is not None else []), KEY_BATCH)
            rows = reader.session.execute(
                f"SELECT job_id FROM {table} WHERE {tenant}=? AND status=?{cursor_sql} ORDER BY job_id LIMIT ?",  # nosec B608
                params,
            ).fetchall()
        if not rows:
            return count
        # The adapter locks and re-reads each source inside the write transaction.
        # An intervening update/deletion therefore cannot resurrect stale data.
        count += store.backfill_finding_history(tenant_id, [row[0] for row in rows])
        after = rows[-1][0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Backfill versioned retained finding history")
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args(argv)
    from agent_bom.api.storage.job_backends import configured_job_store
    from agent_bom.api.tenant_worker import run_tenant_bound

    try:
        count = run_tenant_bound(args.tenant, backfill_tenant_history, configured_job_store(), args.tenant)
    except Exception:  # broad-except: CLI failure reports no source payload, path, or connection secret
        sys.stderr.write("Finding history backfill failed; check tenant, database configuration and migrations.\n")
        return 1
    sys.stdout.write(json.dumps({"tenant_id": args.tenant, "projected_jobs": count}) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
