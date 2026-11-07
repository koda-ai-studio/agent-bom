"""Shared source-based auth backoff and bounded audit admission.

Revision ID: 20261106_01
Revises: 20261105_04
"""

from alembic import op

revision = "20261106_01"
down_revision = "20261105_04"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS public.api_auth_failure_limits (
            source TEXT PRIMARY KEY, failures INTEGER NOT NULL, strikes INTEGER NOT NULL,
            window_start DOUBLE PRECISION NOT NULL, blocked_until DOUBLE PRECISION NOT NULL,
            updated_at DOUBLE PRECISION NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_auth_failure_updated ON public.api_auth_failure_limits(updated_at);
        GRANT SELECT, INSERT, UPDATE, DELETE ON public.api_auth_failure_limits TO agent_bom_app, agent_bom_rls_maintenance;
        INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('auth_failure_limits',1,now())
        ON CONFLICT(component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,1);
    """)


def downgrade() -> None:
    op.execute(
        "DROP TABLE IF EXISTS public.api_auth_failure_limits; "
        "DELETE FROM control_plane_schema_versions WHERE component='auth_failure_limits'"
    )
