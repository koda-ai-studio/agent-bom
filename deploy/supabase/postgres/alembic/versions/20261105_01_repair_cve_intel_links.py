"""Repair CVE links and KEV disagreement left by earlier hub writers.

Findings that carried no intel fields were stored with a blank ``intel_ref``, so they
missed their CVE's KEV verdict in counts. A CVE record could also hold KEV in only
one of its column and payload. This relinks the rows and reconciles the records; KEV
wins when the two disagree.

A separate revision, because ``20261104_01`` is already applied on any database that
tracks main. Blank rows return to the resumable materialization backfill, so reads
label KEV approximate until they finish; batches commit, a rerun or the control
plane's cleanup tick continues, and the tick also finishes the record walk. Expect up
to one extra copy of the blank rows and their indexes on disk.

Fields a replacing writer already overwrote cannot be recovered here: they only come
back from a rescan or a KEV catalog sync.

Revision ID: 20261105_01
Revises: 20261104_01
"""

from __future__ import annotations

import logging
import time

from alembic import op

from agent_bom.api.storage.cve_intel_reconcile import START, link_cve_rows_batch, mark_unlinked_rows_pending, reconcile_intel_batch
from agent_bom.api.storage.finding_materialized import backfill_batch
from agent_bom.api.storage.sql import connection_session

revision = "20261105_01"
down_revision = "20261104_01"
branch_labels = None
depends_on = None

_logger = logging.getLogger("alembic.runtime.migration")
_BATCH_ROWS = 2000
_BUDGET_SECONDS = 1800.0


def _bump_revision(session, tenant: str) -> None:  # type: ignore[no-untyped-def]
    session.execute(
        "INSERT INTO hub_overview_revisions (tenant_id, revision) VALUES (?, 1) "
        "ON CONFLICT (tenant_id) DO UPDATE SET revision = hub_overview_revisions.revision + 1",
        (tenant,),
    )


def _repair(conn) -> None:  # type: ignore[no-untyped-def]
    session = connection_session(conn, "postgres")
    deadline = time.monotonic() + _BUDGET_SECONDS
    # Marking has no budget: a row left unmarked would never be relinked. It is the
    # cheap step, and the backfill that follows is the one the tick can finish.
    after, marked = START, 0
    while after is not None:
        with conn.transaction():
            after, count = mark_unlinked_rows_pending(session, after=after, limit=_BATCH_ROWS)
        marked += count
    materialized = 0
    while time.monotonic() < deadline:
        with conn.transaction():
            done = backfill_batch(session, "postgres", limit=_BATCH_ROWS, bump_revision=_bump_revision)
        materialized += done
        if not done:
            break
    link_after, linked = START, 0
    while link_after is not None and time.monotonic() < deadline:
        with conn.transaction():
            link_after, count = link_cve_rows_batch(session, "postgres", after=link_after, limit=_BATCH_ROWS)
        linked += count
    walk_after, changed = START, 0
    while walk_after is not None and time.monotonic() < deadline:
        with conn.transaction():
            page = reconcile_intel_batch(
                session, "postgres", after=walk_after, limit=_BATCH_ROWS, catalog=None, bump_revision=_bump_revision
            )
        walk_after = page.next_after
        changed += page.changed
    _logger.info("cve intel repair: marked=%d materialized=%d links_checked=%d records_changed=%d", marked, materialized, linked, changed)


def upgrade() -> None:
    bind = op.get_bind()
    current = bind.exec_driver_sql("SELECT to_regclass('public.hub_findings_current')").scalar()
    intel = bind.exec_driver_sql("SELECT to_regclass('public.hub_cve_intel')").scalar()
    if current is None or intel is None:
        return
    with op.get_context().autocommit_block():
        _repair(bind.connection.driver_connection)


def downgrade() -> None:
    # A data repair with no schema change. The linked and reconciled values are valid
    # for every earlier revision, so there is nothing to undo.
    pass
