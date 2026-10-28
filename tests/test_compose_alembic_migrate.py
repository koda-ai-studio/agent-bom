"""Unit tests for deploy/supabase/postgres/compose_migrate.py helpers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.supabase.postgres import compose_migrate as cm


def test_resolve_database_url_requires_explicit_admin_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = tmp_path / "postgres_password"
    secret.write_text("s3cret\n", encoding="utf-8")
    monkeypatch.delenv("ALEMBIC_DATABASE_URL", raising=False)
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://agent_bom@postgres:5432/agent_bom")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_PASSWORD_FILE", str(secret))

    with pytest.raises(SystemExit, match="ALEMBIC_DATABASE_URL"):
        cm._resolve_database_url()


def test_resolve_database_url_keeps_embedded_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_POSTGRES_PASSWORD_FILE", raising=False)
    monkeypatch.setenv(
        "ALEMBIC_DATABASE_URL",
        "postgresql://agent_bom:already@postgres:5432/agent_bom",
    )
    assert cm._resolve_database_url() == "postgresql+psycopg://agent_bom:already@postgres:5432/agent_bom"


def test_resolve_database_url_percent_encodes_spaces_in_userinfo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = tmp_path / "postgres_password"
    secret.write_text("p@ss:/?#%&+ space\n", encoding="utf-8")
    monkeypatch.setenv("ALEMBIC_DATABASE_URL", "postgresql://agent_bom@postgres:5432/agent_bom")
    monkeypatch.setenv("ALEMBIC_DATABASE_PASSWORD_FILE", str(secret))

    assert "p%40ss%3A%2F%3F%23%25%26%2B%20space" in cm._resolve_database_url()


def test_resolve_database_url_uses_distinct_alembic_password_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    admin_secret = tmp_path / "postgres_admin_password"
    admin_secret.write_text("admin:p@ss\n", encoding="utf-8")
    app_secret = tmp_path / "postgres_app_password"
    app_secret.write_text("app-secret\n", encoding="utf-8")
    monkeypatch.setenv("ALEMBIC_DATABASE_URL", "postgresql://agent_bom@postgres:5432/agent_bom")
    monkeypatch.setenv("ALEMBIC_DATABASE_PASSWORD_FILE", str(admin_secret))
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://agent_bom_app@postgres:5432/agent_bom")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_PASSWORD_FILE", str(app_secret))

    url = cm._resolve_database_url()

    assert "agent_bom:admin%3Ap%40ss@postgres" in url
    assert "app-secret" not in url


@pytest.mark.parametrize(
    ("raw", "expected"),
    (
        ("postgres://user@db/app", "postgresql+psycopg://user@db/app"),
        ("postgresql://user@db/app", "postgresql+psycopg://user@db/app"),
        ("postgresql+psycopg://user@db/app", "postgresql+psycopg://user@db/app"),
        ("postgresql+asyncpg://user@db/app", "postgresql+asyncpg://user@db/app"),
    ),
)
def test_normalize_sqlalchemy_url_selects_shipped_driver(raw: str, expected: str) -> None:
    assert cm._normalize_sqlalchemy_url(raw) == expected


def test_alembic_env_normalizes_driverless_postgres_urls() -> None:
    env_source = (Path(__file__).parents[1] / "deploy/supabase/postgres/alembic/env.py").read_text(encoding="utf-8")
    assert "from deploy.supabase.postgres.compose_migrate import" in env_source
    assert "_normalize_sqlalchemy_url," in env_source
    assert "url = _normalize_sqlalchemy_url(url)" in env_source


def test_partition_runway_top_up_runs_on_every_upgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    """Partition provisioning is migration-owned, so each deploy must top it up.

    A one-shot migration would fix the runway once and let it lapse again; the
    top-up has to ride every ``alembic upgrade``.
    """
    from agent_bom.api import hub_observations_partition as partitions

    driver_connection = object()
    connection = SimpleNamespace(connection=SimpleNamespace(driver_connection=driver_connection))
    seen: list[tuple[object, int]] = []

    monkeypatch.setattr(
        partitions,
        "provision_observation_partition_runway",
        lambda conn, **kwargs: seen.append((conn, kwargs.get("months_ahead", partitions.OBSERVATION_PARTITION_RUNWAY_MONTHS))) or 0,
    )

    cm.top_up_observation_partition_runway(connection)

    assert seen == [(driver_connection, partitions.OBSERVATION_PARTITION_RUNWAY_MONTHS)]


def test_partition_runway_top_up_failure_fails_the_deploy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Loud and early: a migration owner that cannot provision must not ship."""
    from agent_bom.api import hub_observations_partition as partitions

    def _boom(_conn: object, **_kwargs: object) -> int:
        raise RuntimeError("permission denied for schema public")

    monkeypatch.setattr(partitions, "provision_observation_partition_runway", _boom)
    connection = SimpleNamespace(connection=SimpleNamespace(driver_connection=object()))

    with pytest.raises(RuntimeError, match="permission denied"):
        cm.top_up_observation_partition_runway(connection)


def test_alembic_env_tops_up_the_partition_runway_after_migrations() -> None:
    env_source = (Path(__file__).parents[1] / "deploy/supabase/postgres/alembic/env.py").read_text(encoding="utf-8")
    assert "top_up_observation_partition_runway" in env_source
    run_at = env_source.index("context.run_migrations()")
    top_up_at = env_source.index("top_up_observation_partition_runway(connection)")
    assert top_up_at > run_at, "the runway top-up must run after the migrations, not before"


def test_alembic_env_never_falls_back_to_the_runtime_app_url() -> None:
    env_source = (Path(__file__).parents[1] / "deploy/supabase/postgres/alembic/env.py").read_text(encoding="utf-8")

    assert 'os.environ.get("ALEMBIC_DATABASE_URL") or os.environ.get("AGENT_BOM_POSTGRES_URL")' not in env_source
    assert "Set ALEMBIC_DATABASE_URL before running Alembic migrations." in env_source


def test_main_reconciles_runtime_role_passwords_after_every_upgrade(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[object] = []
    monkeypatch.setattr(cm, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cm, "_resolve_database_url", lambda: "postgresql+psycopg://admin@db/app")
    monkeypatch.setattr(cm, "_needs_baseline_stamp", lambda _url: False)
    monkeypatch.setattr(cm, "_run_alembic", lambda _root, *args: calls.append(args))
    monkeypatch.setattr(cm, "_reconcile_runtime_role_passwords", lambda url: calls.append(("reconcile", url)))

    assert cm.main() == 0
    assert calls == [
        (cm.ALEMBIC_CONFIG, "upgrade", "head"),
        ("reconcile", "postgresql+psycopg://admin@db/app"),
    ]


def test_main_preserves_custom_alembic_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(cm, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cm, "_resolve_database_url", lambda: "postgresql+psycopg://admin@db/app")
    monkeypatch.setattr(cm, "_needs_baseline_stamp", lambda _url: False)
    monkeypatch.setattr(cm, "_run_alembic", lambda _root, *args: calls.append(args))
    monkeypatch.setattr(cm, "_reconcile_runtime_role_passwords", lambda _url: None)

    assert cm.main(["--config", "deploy/custom-alembic.ini"]) == 0
    assert calls == [("deploy/custom-alembic.ini", "upgrade", "head")]


def test_bootstrap_passwords_are_bound_before_fresh_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fresh RDS has no app login; baseline role creation needs both secrets."""
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://agent_bom_app:app%27secret@db/app")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_MAINTENANCE_URL", "postgresql://agent_bom_maintenance:maintenance-secret@db/app")
    monkeypatch.delenv("AGENT_BOM_POSTGRES_PASSWORD_FILE", raising=False)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_MAINTENANCE_PASSWORD_FILE", raising=False)
    calls: list[tuple[str, tuple[str, str]]] = []
    connection = SimpleNamespace(exec_driver_sql=lambda sql, parameters: calls.append((sql, parameters)))
    cm.configure_bootstrap_credentials(connection)
    assert [parameters for _, parameters in calls] == [
        ("init.app_password", "app'secret"),
        ("init.maintenance_password", "maintenance-secret"),
    ]
    assert all(sql == "SELECT set_config(%s, %s, true)" for sql, _ in calls)
    env_source = (Path(__file__).parents[1] / "deploy/supabase/postgres/alembic/env.py").read_text()
    online = env_source.split("def run_migrations_online()", 1)[1]
    assert (
        online.index("with context.begin_transaction():")
        < online.index("configure_bootstrap_credentials(connection)")
        < online.index("context.run_migrations()")
    )
    assert "hide_parameters=True" in online


@pytest.mark.parametrize("url", ["postgresql://unexpected:secret@db/app", "postgresql://agent_bom_app@db/app"])
def test_bootstrap_credentials_reject_rebinding_and_empty_password(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", url)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_PASSWORD_FILE", raising=False)
    calls: list[object] = []
    with pytest.raises(SystemExit):
        cm.configure_bootstrap_credentials(SimpleNamespace(exec_driver_sql=lambda *args: calls.append(args)))
    assert calls == []


def test_bootstrap_credentials_preserve_out_of_band_role_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_MAINTENANCE_URL", raising=False)
    calls: list[object] = []
    cm.configure_bootstrap_credentials(SimpleNamespace(exec_driver_sql=lambda *args: calls.append(args)))
    assert calls == []


class _RoleConnection:
    def __init__(self, role: str) -> None:
        self.role = role
        self.statements: list[str] = []

    def exec_driver_sql(self, sql: str, *args: object):
        self.statements.append(sql)
        return SimpleNamespace(scalar=lambda: self.role)


@pytest.mark.parametrize("role", ["agent_bom_app", "agent_bom_rls_maintenance"])
def test_migration_role_preflight_refuses_runtime_roles(role: str) -> None:
    """``20261023_02`` revokes ledger writes from runtime roles; migrating as one would self-revoke."""
    connection = _RoleConnection(role)
    with pytest.raises(RuntimeError) as excinfo:
        cm.assert_migration_role(connection)
    message = str(excinfo.value)
    assert role in message
    assert "ALEMBIC_DATABASE_URL" in message
    assert "admin" in message.lower()
    assert connection.statements == ["SELECT current_user"]


@pytest.mark.parametrize("role", ["postgres", "agentbom_migration_owner", "agent_bom_maintenance"])
def test_migration_role_preflight_allows_other_identities(role: str) -> None:
    connection = _RoleConnection(role)
    assert cm.assert_migration_role(connection) == role


def test_alembic_env_checks_the_migration_role_before_any_migration_runs() -> None:
    env_source = (Path(__file__).parents[1] / "deploy/supabase/postgres/alembic/env.py").read_text(encoding="utf-8")
    online = env_source.split("def run_migrations_online()", 1)[1]
    assert online.index("assert_migration_role(connection)") < online.index("configure_bootstrap_credentials(connection)")
    assert online.index("assert_migration_role(connection)") < online.index("context.run_migrations()")
