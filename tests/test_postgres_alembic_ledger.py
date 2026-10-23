"""Only the migration identity writes ``alembic_version``; runtime roles keep read access."""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

POSTGRES_DIR = Path(__file__).parent.parent / "deploy" / "supabase" / "postgres"
MIGRATION = POSTGRES_DIR / "alembic" / "versions" / "20261023_02_alembic_version_read_only.py"
_REVOKE = re.compile(r"REVOKE\s+INSERT,\s*UPDATE,\s*DELETE,\s*TRUNCATE\s+ON\s+(?:TABLE\s+)?public\.alembic_version", re.I)
_RIGHTS = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")


def test_runtime_roles_cannot_write_the_migration_ledger_on_any_bootstrap_path() -> None:
    source = MIGRATION.read_text()
    assert re.search(r'^revision\s*=\s*"20261023_02"', source, re.M)
    assert re.search(r'^down_revision\s*=\s*"20261023_01"', source, re.M)
    for path in (MIGRATION, POSTGRES_DIR / "init.sql", POSTGRES_DIR / "runtime-schema.sql"):
        text = path.read_text()
        assert "agent_bom_app" in text and "agent_bom_rls_maintenance" in text, path.name
        assert _REVOKE.search(text), path.name


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="AGENT_BOM_POSTGRES_URL is required for the live grant check")
def test_postgres_app_role_reads_but_never_writes_the_migration_ledger() -> None:
    from agent_bom.api.postgres_common import _get_pool

    with _get_pool().connection() as conn:
        rights = conn.execute(
            "SELECT " + ", ".join(f"has_table_privilege(current_user, 'public.alembic_version', '{right}')" for right in _RIGHTS)
        ).fetchone()
    assert dict(zip(_RIGHTS, rights)) == {"SELECT": True, "INSERT": False, "UPDATE": False, "DELETE": False, "TRUNCATE": False}
