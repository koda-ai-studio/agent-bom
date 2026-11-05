"""Materialize KEV, issue-group, coverage and framework keys on current findings.

Payloads of 512 bytes or more are zstd-wrapped, so SQL reading keys inside them
undercounted KEV (0 of 5,000 at one million rows) and joined the whole table to
find out. These columns make those counts exact and sargable.

The ALTERs are catalog-only under a short lock timeout. ``issue_group_id IS NULL``
marks a row as pending, so the backfill is resumable: every batch commits, and a
rerun or the control plane's cleanup tick continues from what is left. Reads label
KEV approximate and walk compressed payloads until the tenant has no pending rows.

Expect up to one extra copy of the table and its indexes on disk during the
backfill; vacuum makes that space reusable afterwards.

Revision ID: 20261104_01
Revises: 20261102_10
"""

from __future__ import annotations

import logging
import time

from alembic import op

from agent_bom.api.storage.finding_materialized import (
    INTEL_KEV_BACKFILL_POSTGRES,
    MATERIALIZED_POSTGRES_COLUMNS,
    PENDING_INDEX,
    READ_INDEXES,
    backfill_batch,
)
from agent_bom.api.storage.sql import connection_session

revision = "20261104_01"
down_revision = "20261102_10"
branch_labels = None
depends_on = None

_logger = logging.getLogger("alembic.runtime.migration")
_BATCH_ROWS = 2000
_BACKFILL_BUDGET_SECONDS = 1800.0
_INDEX_NAMES = (
    "idx_hub_findings_current_materialize_pending",
    "idx_hub_findings_current_issue_group",
    "idx_hub_findings_current_kev_direct",
    "idx_hub_findings_current_intel_ref",
    "idx_hub_cve_intel_kev",
)


def _concurrently(statement: str) -> str:
    return statement.replace("CREATE INDEX IF NOT EXISTS", "CREATE INDEX CONCURRENTLY IF NOT EXISTS", 1)


def _bump_revision(session, tenant: str) -> None:  # type: ignore[no-untyped-def]
    session.execute(
        "INSERT INTO hub_overview_revisions (tenant_id, revision) VALUES (?, 1) "
        "ON CONFLICT (tenant_id) DO UPDATE SET revision = hub_overview_revisions.revision + 1",
        (tenant,),
    )


def _backfill(driver_connection) -> int:  # type: ignore[no-untyped-def]
    """Materialize existing rows until done or out of budget; the cleanup tick finishes the rest."""
    session = connection_session(driver_connection, "postgres")
    deadline = time.monotonic() + _BACKFILL_BUDGET_SECONDS
    total = 0
    while time.monotonic() < deadline:
        with driver_connection.transaction():
            done = backfill_batch(session, "postgres", limit=_BATCH_ROWS, bump_revision=_bump_revision)
        total += done
        if not done:
            break
    return total


def upgrade() -> None:
    bind = op.get_bind()
    current = bind.exec_driver_sql("SELECT to_regclass('public.hub_findings_current')").scalar()
    intel = bind.exec_driver_sql("SELECT to_regclass('public.hub_cve_intel')").scalar()
    op.execute("""INSERT INTO control_plane_schema_versions(component, version, updated_at)
        VALUES ('compliance_hub', 4, now()) ON CONFLICT(component)
        DO UPDATE SET version=GREATEST(control_plane_schema_versions.version, 4), updated_at=now()""")
    # Minimal stamped deployments create these tables with the columns already present.
    if current is None or intel is None:
        return
    op.execute("SET LOCAL lock_timeout = '30s'")
    for statement in MATERIALIZED_POSTGRES_COLUMNS:
        op.execute(statement)
    op.execute(INTEL_KEV_BACKFILL_POSTGRES)
    # CONCURRENTLY keeps ingest writing; the read indexes follow the backfill so it
    # does not pay to maintain them row by row.
    with op.get_context().autocommit_block():
        op.execute(_concurrently(PENDING_INDEX))
        done = _backfill(bind.connection.driver_connection)
        _logger.info("hub_findings_current: materialized %d rows", done)
        for statement in READ_INDEXES:
            op.execute(_concurrently(statement))


def downgrade() -> None:
    # Dropping is catalog-only. A later upgrade recomputes every row, so values
    # cannot go stale across a period of older writers.
    with op.get_context().autocommit_block():
        for name in _INDEX_NAMES:
            op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {name}")
    for column in ("issue_group_id", "kev_direct", "intel_ref", "lens_mask", "frameworks_csv"):
        op.execute(f"ALTER TABLE IF EXISTS hub_findings_current DROP COLUMN IF EXISTS {column}")
    op.execute("ALTER TABLE IF EXISTS hub_cve_intel DROP COLUMN IF EXISTS is_kev")
    op.execute("UPDATE control_plane_schema_versions SET version = 3, updated_at = now() WHERE component = 'compliance_hub'")
