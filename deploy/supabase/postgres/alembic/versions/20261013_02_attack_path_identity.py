"""Key persisted attack paths by route occurrence and keep their finding ids.

The legacy key (source_node, target_node, scan_id, tenant_id) collapsed two
distinct routes between the same endpoints into one row, last writer wins.
Rows are re-keyed by (tenant_id, scan_id, path_key) with the same hop/edge
chain hash the snapshot path index uses; existing rows get their computed key.

Revision ID: 20261013_02
Revises: 20261013_01
"""

from __future__ import annotations

import sys
from pathlib import Path

from alembic import op

revision = "20261013_02"
down_revision = "20261013_01"
branch_labels = None
depends_on = None

_REPO_ROOT = Path(__file__).resolve().parents[5]
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agent_bom.api.postgres_graph_path_identity import upgrade_attack_path_identity  # noqa: E402


def upgrade() -> None:
    # attack_paths enforces FORCE ROW LEVEL SECURITY; the key backfill must see
    # every tenant's rows, so it runs under the transaction-local bypass GUC.
    op.execute("SELECT set_config('app.bypass_rls', '1', true)")
    upgrade_attack_path_identity(op.get_bind().connection.driver_connection)
    op.execute("""
        UPDATE control_plane_schema_versions SET version=8,updated_at=now()
        WHERE component='graph' AND version=7
    """)


def downgrade() -> None:
    # The older key holds one route per endpoint pair: keep the highest-risk one.
    op.execute("SELECT set_config('app.bypass_rls', '1', true)")
    op.execute("""
        DELETE FROM attack_paths a
        USING attack_paths b
        WHERE a.tenant_id = b.tenant_id AND a.scan_id = b.scan_id
          AND a.source_node = b.source_node AND a.target_node = b.target_node
          AND (a.composite_risk, a.path_key) < (b.composite_risk, b.path_key)
    """)
    op.execute("ALTER TABLE attack_paths DROP CONSTRAINT IF EXISTS attack_paths_pkey")
    op.execute("ALTER TABLE attack_paths ADD CONSTRAINT attack_paths_pkey PRIMARY KEY (source_node, target_node, scan_id, tenant_id)")
    op.execute("ALTER TABLE attack_paths DROP COLUMN IF EXISTS path_key")
    op.execute("ALTER TABLE attack_paths DROP COLUMN IF EXISTS finding_ids")
    op.execute("UPDATE control_plane_schema_versions SET version=7,updated_at=now() WHERE component='graph' AND version=8")
