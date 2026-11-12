"""Raise the application role's connection limit above one process's pools.

``init.sql`` capped ``agent_bom_app`` at 20 connections. One API process can
open 32 (a main pool of up to 20, admission and idempotency pools of 4 each,
and up to 4 graph-build connections) and keeps about 7 open while idle, so a
second replica, a rolling-update surge pod or the post-install verification
Job was refused with ``too many connections for role "agent_bom_app"``.

Raise a bounded limit below 100 to 100. Unlimited (-1) and higher limits are
kept. Helm installs then raise both runtime roles further from their replica
counts after every upgrade (``compose_migrate.py``). A migration role that
cannot administer ``agent_bom_app`` leaves the limit alone with a warning
rather than failing the upgrade.

Revision ID: 20261112_01
Revises: 20261111_01
"""

from __future__ import annotations

from alembic import op

revision = "20261112_01"
down_revision = "20261111_01"
branch_labels = None
depends_on = None

_CAN_ADMINISTER = """
    SELECT s.rolsuper OR (s.rolcreaterole AND EXISTS (
      SELECT 1 FROM pg_auth_members m WHERE m.member = s.oid AND m.roleid = t.oid AND m.admin_option
    ))
    FROM pg_roles s, pg_roles t
    WHERE s.rolname = session_user AND t.rolname = 'agent_bom_app'
"""


def _set_limit(when: str, limit: int) -> str:
    warning = (
        "agent_bom_app CONNECTION LIMIT unchanged: the migration role cannot administer it; "
        f"run ALTER ROLE agent_bom_app CONNECTION LIMIT {limit}"
    )
    return f"""
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app' AND {when}) THEN
        IF ({_CAN_ADMINISTER}) THEN
            ALTER ROLE agent_bom_app CONNECTION LIMIT {limit};
        ELSE
            RAISE WARNING '{warning}';
        END IF;
    END IF;
END
$$;
"""


def upgrade() -> None:
    op.execute(_set_limit("rolconnlimit BETWEEN 0 AND 99", 100))


def downgrade() -> None:
    op.execute(_set_limit("rolconnlimit = 100", 20))
