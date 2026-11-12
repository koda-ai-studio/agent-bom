"""Runtime role connection limits cover every process that connects, on every upgrade."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from typing import Any

import pytest

from deploy.supabase.postgres import compose_migrate as cm

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "deploy/supabase/postgres/alembic/versions/20261112_01_runtime_role_connection_limits.py"


class _Cursor:
    def __init__(self, row: tuple[Any, ...] | None) -> None:
        self._row = row

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row


class _Connection:
    """pg_roles rows as {role: (rolconnlimit, migration role can alter it)}."""

    def __init__(self, roles: dict[str, tuple[int, bool]], max_connections: int = 500) -> None:
        self.roles = roles
        self.max_connections = max_connections
        self.statements: list[str] = []

    def execute(self, statement: str, params: tuple[Any, ...] = ()) -> _Cursor:
        if statement.startswith("ALTER ROLE"):
            self.statements.append(statement)
            role, limit = re.fullmatch(r"ALTER ROLE (\w+) CONNECTION LIMIT (\d+)", statement).groups()  # type: ignore[union-attr]
            self.roles[role] = (int(limit), self.roles[role][1])
            return _Cursor(None)
        if "max_connections" in statement:
            return _Cursor((str(self.max_connections),))
        return _Cursor(self.roles.get(params[-1]))


def test_required_limits_come_from_the_chart_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_POSTGRES_APP_CONNECTION_LIMIT", raising=False)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_MAINTENANCE_CONNECTION_LIMIT", raising=False)
    assert cm.required_connection_limits() == {}
    monkeypatch.setenv("AGENT_BOM_POSTGRES_APP_CONNECTION_LIMIT", "133")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_MAINTENANCE_CONNECTION_LIMIT", "20")
    assert cm.required_connection_limits() == {"agent_bom_app": 133, "agent_bom_maintenance": 20}


@pytest.mark.parametrize("raw", ["many", "0", "-5"])
def test_an_unusable_required_limit_fails_the_migration(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv("AGENT_BOM_POSTGRES_APP_CONNECTION_LIMIT", raw)
    with pytest.raises(SystemExit, match="AGENT_BOM_POSTGRES_APP_CONNECTION_LIMIT"):
        cm.required_connection_limits()


def test_a_limit_below_demand_is_raised() -> None:
    connection = _Connection({"agent_bom_app": (20, True), "agent_bom_maintenance": (32, True)})
    cm.reconcile_connection_limits(connection, {"agent_bom_app": 133, "agent_bom_maintenance": 20})
    assert connection.statements == ["ALTER ROLE agent_bom_app CONNECTION LIMIT 133"]
    assert connection.roles["agent_bom_app"][0] == 133


@pytest.mark.parametrize("current", [-1, 133, 400])
def test_unlimited_or_higher_limits_are_never_lowered(current: int) -> None:
    connection = _Connection({"agent_bom_app": (current, True)})
    cm.reconcile_connection_limits(connection, {"agent_bom_app": 133})
    assert connection.statements == []


def test_a_limit_the_migration_role_cannot_raise_fails_with_the_fix() -> None:
    connection = _Connection({"agent_bom_app": (20, False)})
    with pytest.raises(SystemExit) as excinfo:
        cm.reconcile_connection_limits(connection, {"agent_bom_app": 133})
    message = str(excinfo.value)
    assert "ALTER ROLE agent_bom_app CONNECTION LIMIT 133" in message
    assert "20" in message
    assert connection.statements == []


def test_a_role_provisioned_out_of_band_later_is_skipped(capsys: pytest.CaptureFixture[str]) -> None:
    connection = _Connection({})
    cm.reconcile_connection_limits(connection, {"agent_bom_app": 133})
    assert connection.statements == []
    assert "role agent_bom_app does not exist" in capsys.readouterr().out


def test_server_max_connections_below_the_role_limits_is_reported(capsys: pytest.CaptureFixture[str]) -> None:
    connection = _Connection({"agent_bom_app": (20, True), "agent_bom_maintenance": (32, True)}, max_connections=100)
    cm.reconcile_connection_limits(connection, {"agent_bom_app": 133, "agent_bom_maintenance": 20})
    out = capsys.readouterr().out
    assert "max_connections=100" in out
    assert "153" in out


def test_main_reconciles_limits_after_passwords(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[object] = []
    monkeypatch.setattr(cm, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cm, "_resolve_database_url", lambda: "postgresql+psycopg://admin@db/app")
    monkeypatch.setattr(cm, "_needs_baseline_stamp", lambda _url: False)
    monkeypatch.setattr(cm, "_run_alembic", lambda _root, *args: calls.append(args))
    monkeypatch.setattr(cm, "_reconcile_runtime_role_passwords", lambda url: calls.append(("passwords", url)))
    monkeypatch.setattr(cm, "_reconcile_runtime_role_connection_limits", lambda url: calls.append(("limits", url)))
    assert cm.main() == 0
    assert calls[-2:] == [("passwords", "postgresql+psycopg://admin@db/app"), ("limits", "postgresql+psycopg://admin@db/app")]


def _migration() -> Any:
    spec = importlib.util.spec_from_file_location("connection_limits_migration", MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_revision_follows_the_previous_head() -> None:
    module = _migration()
    assert (module.revision, module.down_revision) == ("20261112_01", "20261111_01")


def test_upgrade_raises_bounded_limits_and_downgrade_restores_only_its_own(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _migration()
    executed: list[str] = []
    monkeypatch.setattr(module.op, "execute", lambda statement: executed.append(str(statement)), raising=False)
    module.upgrade()
    upgrade_sql = "\n".join(executed)
    assert "rolconnlimit BETWEEN 0 AND 99" in upgrade_sql
    assert "CONNECTION LIMIT 100" in upgrade_sql
    assert "agent_bom_app" in upgrade_sql
    assert "RAISE WARNING" in upgrade_sql
    executed.clear()
    module.downgrade()
    downgrade_sql = "\n".join(executed)
    assert "rolconnlimit = 100" in downgrade_sql
    assert "CONNECTION LIMIT 20" in downgrade_sql
