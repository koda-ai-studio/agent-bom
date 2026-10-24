"""A control plane that cannot initialize must refuse to start, not serve 500s."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import psycopg
import pytest
import uvicorn
from click.testing import CliRunner
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from uvicorn.lifespan.on import LifespanOn

from agent_bom.api.middleware_limits import RateLimitMiddleware, _build_rate_limit_store
from agent_bom.api.storage_schema import ensure_postgres_schema_version
from agent_bom.cli import main


class _FailingConn:
    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def execute(self, *args, **kwargs):
        raise self._exc


def _limited_app() -> Starlette:
    async def ok(request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/health", ok)])
    app.add_middleware(RateLimitMiddleware, scan_rpm=3, read_rpm=10, get_key_store=lambda: None)
    return app


def _lifespan_should_exit(app: Starlette, mode: str) -> bool:
    lifespan = LifespanOn(uvicorn.Config(app, lifespan=mode))
    asyncio.run(lifespan.startup())
    return lifespan.should_exit


@pytest.mark.parametrize("command", ["serve", "api"])
def test_server_commands_run_uvicorn_with_lifespan_required(monkeypatch, command):
    seen: dict[str, object] = {}
    monkeypatch.setenv("AGENT_BOM_NO_AUTO_DEV_KEY", "1")
    monkeypatch.setattr(uvicorn, "run", lambda *args, **kwargs: seen.update(kwargs))

    args = [command, "--no-ui"] if command == "serve" else [command]
    result = CliRunner().invoke(main, args)

    assert result.exit_code == 0, result.output
    assert seen.get("lifespan") == "on"


def test_limiter_init_failure_aborts_startup_when_lifespan_required(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://example/test")
    with patch("agent_bom.api.middleware_limits.PostgresRateLimitStore", side_effect=RuntimeError("boom")):
        assert _lifespan_should_exit(_limited_app(), "on") is True
        # uvicorn's default swallows the same failure as "lifespan unsupported"
        # and keeps serving; this is why the server commands must pin "on".
        assert _lifespan_should_exit(_limited_app(), "auto") is False


def test_limiter_init_failure_names_the_cause(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://example/test")
    cause = RuntimeError("Postgres schema component 'rate_limits' is not migrated")
    with patch("agent_bom.api.middleware_limits.PostgresRateLimitStore", side_effect=cause):
        with pytest.raises(RuntimeError) as excinfo:
            _build_rate_limit_store(60)
    message = str(excinfo.value)
    assert "Configured Postgres rate limiter could not initialize" in message
    assert "'rate_limits' is not migrated" in message


def test_missing_schema_ledger_says_to_run_migrations(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://example/test")
    conn = _FailingConn(psycopg.errors.UndefinedTable('relation "control_plane_schema_versions" does not exist'))

    with pytest.raises(RuntimeError) as excinfo:
        ensure_postgres_schema_version(conn, "rate_limits")

    message = str(excinfo.value)
    assert "has not been migrated" in message
    assert "compose_migrate.py" in message
    assert "AGENT_BOM_POSTGRES_URL" in message


def test_unreadable_schema_ledger_names_the_runtime_role_grant(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://example/test")
    conn = _FailingConn(psycopg.errors.InsufficientPrivilege("permission denied for table control_plane_schema_versions"))

    with pytest.raises(RuntimeError) as excinfo:
        ensure_postgres_schema_version(conn, "api_keys")

    message = str(excinfo.value)
    assert "cannot read control_plane_schema_versions" in message
    assert "agent_bom_app" in message
