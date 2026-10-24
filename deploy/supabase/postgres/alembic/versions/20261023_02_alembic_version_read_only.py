"""Keep the Alembic ledger read-only for runtime roles.

Broad ``ON ALL TABLES`` grants and default privileges handed the app and RLS
maintenance roles INSERT/UPDATE/DELETE on ``alembic_version``. Only the
migration identity (compose ``migrate`` / the Helm pre-upgrade Job, both on the
admin URL) writes it; runtime code only probes that it exists. Read access stays.

Rollback keeps the tighter privileges: no previous version writes the ledger
from a runtime role.
"""

from alembic import op

revision = "20261023_02"
down_revision = "20261023_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $ledger$
        BEGIN
            IF to_regclass('public.alembic_version') IS NOT NULL THEN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
                    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE public.alembic_version FROM agent_bom_app;
                END IF;
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_rls_maintenance') THEN
                    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE public.alembic_version FROM agent_bom_rls_maintenance;
                END IF;
            END IF;
        END $ledger$
    """)


def downgrade() -> None:
    pass
