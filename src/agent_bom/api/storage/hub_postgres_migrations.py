"""Idempotent Postgres compliance-ledger schema migrations."""

from __future__ import annotations

from typing import Any


def _migrate_lifecycle_observations_l2_postgres(conn: Any) -> None:
    """Upgrade L1 observation rows (PK on observed_at) to L2 (PK on scan_id)."""
    conn.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = current_schema()
                  AND table_name = 'hub_findings_current_observations'
            ) THEN
                RETURN;
            END IF;
            IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'hub_findings_current_observations'
                  AND column_name = 'scan_id'
            ) THEN
                RETURN;
            END IF;
            ALTER TABLE hub_findings_current_observations
                RENAME TO hub_findings_current_observations_l1;
            CREATE TABLE hub_findings_current_observations (
                tenant_id TEXT NOT NULL,
                canonical_id TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, canonical_id, scan_id)
            );
            INSERT INTO hub_findings_current_observations
                (tenant_id, canonical_id, scan_id, observed_at)
            SELECT tenant_id, canonical_id, observed_at, observed_at
            FROM hub_findings_current_observations_l1;
            DROP TABLE hub_findings_current_observations_l1;
        END $$;
        """
    )


def _migrate_current_ledger_ref_postgres(conn: Any) -> None:
    conn.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'hub_findings_current'
                  AND column_name = 'ledger_finding_id'
            ) THEN
                ALTER TABLE hub_findings_current ADD COLUMN ledger_finding_id TEXT;
            END IF;
        END $$;
        """
    )


def _migrate_current_ledger_ordinal_postgres(conn: Any) -> None:
    """Materialise the ledger ingest ``ordinal`` onto ``hub_findings_current``.

    Postgres mirror of the SQLite migration (#3984): promote ``sort=ordinal``
    off a per-row correlated ledger subquery onto a stored column backed by
    ``idx_hub_findings_current_tenant_ordinal``. The guarded ALTER seeds
    pre-existing rows with the ``MAX(bigint)`` sort sentinel; the one-shot
    backfill resolves the real ordinal for rows with a ledger pointer, matching
    the old ``COALESCE(subquery, 9223372036854775807)`` value. Idempotent: the
    backfill only runs while the column is freshly added and no-ops on empty
    tables. Requires ``ledger_finding_id`` to already exist.
    """
    conn.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'hub_findings_current'
                  AND column_name = 'ledger_ordinal'
            ) THEN
                ALTER TABLE hub_findings_current
                    ADD COLUMN ledger_ordinal BIGINT NOT NULL DEFAULT 9223372036854775807;
                UPDATE hub_findings_current c SET ledger_ordinal = COALESCE(
                    (
                        SELECT f.ordinal FROM compliance_hub_findings f
                        WHERE f.tenant_id = c.tenant_id
                          AND f.finding_id = c.ledger_finding_id
                        LIMIT 1
                    ),
                    9223372036854775807
                )
                WHERE c.ledger_finding_id IS NOT NULL AND c.ledger_finding_id <> '';
            END IF;
        END $$;
        """
    )
