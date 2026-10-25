"""Key managed identities by (tenant_id, identity_id).

``identity_id`` alone was the primary key, so a second tenant holding the same
identity id (the deterministic demo identities, or any operator-chosen id)
hit the first tenant's row on upsert and failed with a row-level-security
violation instead of landing as its own row. The token hash stays globally
unique: token resolution happens before the tenant is known.

Revision ID: 20261024_02
Revises: 20261024_01
"""

from __future__ import annotations

from alembic import op

revision = "20261024_02"
down_revision = "20261024_01"
branch_labels = None
depends_on = None

_VERSION_SQL = (
    "INSERT INTO control_plane_schema_versions(component, version, updated_at) VALUES ('agent_identities', {version}, NOW()) "
    "ON CONFLICT(component) DO UPDATE SET version = {merge}, updated_at = EXCLUDED.updated_at"
)


def _table_exists() -> bool:
    return op.get_bind().exec_driver_sql("SELECT to_regclass('public.agent_identities')").scalar() is not None


def upgrade() -> None:
    if not _table_exists():
        return
    op.execute("ALTER TABLE public.agent_identities DROP CONSTRAINT IF EXISTS agent_identities_pkey")
    op.execute("ALTER TABLE public.agent_identities ADD CONSTRAINT agent_identities_pkey PRIMARY KEY (tenant_id, identity_id)")
    op.execute(_VERSION_SQL.format(version=3, merge="GREATEST(control_plane_schema_versions.version, EXCLUDED.version)"))


def downgrade() -> None:
    if not _table_exists():
        return
    shared = op.get_bind().exec_driver_sql(
        "SELECT count(*) FROM (SELECT identity_id FROM public.agent_identities GROUP BY identity_id HAVING count(*) > 1) AS shared"
    )
    if int(shared.scalar() or 0):
        raise RuntimeError(
            "agent_identities holds the same identity_id in more than one tenant; "
            "an identity_id-only primary key would drop one tenant's identity. Resolve those rows before downgrading."
        )
    op.execute("ALTER TABLE public.agent_identities DROP CONSTRAINT IF EXISTS agent_identities_pkey")
    op.execute("ALTER TABLE public.agent_identities ADD CONSTRAINT agent_identities_pkey PRIMARY KEY (identity_id)")
    op.execute(_VERSION_SQL.format(version=2, merge="EXCLUDED.version"))
