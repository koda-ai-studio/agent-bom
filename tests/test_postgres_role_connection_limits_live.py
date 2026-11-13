"""Real Postgres: the connection-limit revision and reconcile raise bounded limits and keep a locked role locked.

Every case runs inside one transaction that is rolled back (``ALTER ROLE`` is
transactional), so the shared ``agent_bom_app`` role the other suites log in
as is never left changed.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

ADMIN_URL = os.environ.get("AGENT_BOM_POSTGRES_ADMIN_URL", "")
pytestmark = pytest.mark.skipif(not ADMIN_URL, reason="requires a private Postgres admin DSN")

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "deploy/supabase/postgres/alembic/versions/20261112_01_runtime_role_connection_limits.py"
COMPOSE_MIGRATE = ROOT / "deploy/supabase/postgres/compose_migrate.py"


def _load(path: Path, name: str, monkeypatch: pytest.MonkeyPatch) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def admin() -> Iterator[Any]:
    psycopg = pytest.importorskip("psycopg")
    conn = psycopg.connect(ADMIN_URL)
    notices: list[str] = []
    conn.add_notice_handler(lambda diag: notices.append(f"{diag.severity}: {diag.message_primary}"))
    conn.notices = notices  # type: ignore[attr-defined]
    exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app'").fetchone()
    if not exists:
        conn.execute("CREATE ROLE agent_bom_app LOGIN")
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


def _revision(monkeypatch: pytest.MonkeyPatch, conn: Any) -> Any:
    monkeypatch.setitem(sys.modules, "alembic", SimpleNamespace(op=SimpleNamespace(execute=lambda statement: conn.execute(statement))))
    return _load(MIGRATION, "connection_limits_revision_live", monkeypatch)


def _limit(conn: Any) -> int:
    return int(conn.execute("SELECT rolconnlimit FROM pg_roles WHERE rolname = 'agent_bom_app'").fetchone()[0])


@pytest.mark.parametrize(("start", "after_upgrade", "after_downgrade"), [(20, 100, 20), (1, 100, 20), (-1, -1, -1), (150, 150, 150)])
def test_upgrade_raises_bounded_limits_and_downgrade_reverses_it(monkeypatch, admin, start, after_upgrade, after_downgrade) -> None:
    module = _revision(monkeypatch, admin)
    admin.execute(f"ALTER ROLE agent_bom_app CONNECTION LIMIT {start}")
    module.upgrade()
    assert _limit(admin) == after_upgrade
    module.upgrade()
    assert _limit(admin) == after_upgrade
    module.downgrade()
    assert _limit(admin) == after_downgrade


def test_a_locked_role_stays_locked_through_upgrade_and_downgrade(monkeypatch, admin) -> None:
    module = _revision(monkeypatch, admin)
    admin.execute("ALTER ROLE agent_bom_app CONNECTION LIMIT 0")
    module.upgrade()
    assert _limit(admin) == 0
    assert any(n.startswith("WARNING") and "CONNECTION LIMIT 0" in n for n in admin.notices)
    module.downgrade()
    assert _limit(admin) == 0


def test_a_migration_role_without_admin_option_leaves_the_limit_with_a_warning(monkeypatch, admin) -> None:
    module = _revision(monkeypatch, admin)
    admin.execute("ALTER ROLE agent_bom_app CONNECTION LIMIT 20")
    admin.execute("CREATE ROLE abom_live_migrator_noadmin LOGIN CREATEROLE")
    admin.execute("SET SESSION AUTHORIZATION abom_live_migrator_noadmin")
    module.upgrade()
    admin.execute("RESET SESSION AUTHORIZATION")
    assert _limit(admin) == 20
    assert any(n.startswith("WARNING") and "cannot administer" in n for n in admin.notices)


def test_reconcile_keeps_a_locked_role_and_raises_a_bounded_one(monkeypatch, admin, capsys) -> None:
    cm = _load(COMPOSE_MIGRATE, "compose_migrate_live", monkeypatch)
    admin.execute("ALTER ROLE agent_bom_app CONNECTION LIMIT 0")
    cm.reconcile_connection_limits(admin, {"agent_bom_app": 133})
    assert _limit(admin) == 0
    assert "CONNECTION LIMIT is 0" in capsys.readouterr().out

    admin.execute("ALTER ROLE agent_bom_app CONNECTION LIMIT 20")
    cm.reconcile_connection_limits(admin, {"agent_bom_app": 133})
    assert _limit(admin) == 133
