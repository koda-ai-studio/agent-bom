"""The tenant session prelude pipelines only real psycopg connections and works without psycopg installed."""

from __future__ import annotations

import sys

import pytest

from agent_bom.api import postgres_common
from agent_bom.api.postgres_session_pipeline import session_pipeline


class _StandIn:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple]] = []
        self.pipelines = 0

    def execute(self, sql: str, params: tuple = ()) -> None:
        self.executed.append((sql, params))

    def pipeline(self):  # pragma: no cover - must never be entered for a stand-in
        self.pipelines += 1
        raise AssertionError("a stand-in connection is never pipelined")


@pytest.mark.parametrize("psycopg_installed", [True, False])
def test_stand_in_connections_send_the_prelude_directly(monkeypatch: pytest.MonkeyPatch, psycopg_installed: bool) -> None:
    if not psycopg_installed:
        monkeypatch.setitem(sys.modules, "psycopg", None)
    monkeypatch.setattr(postgres_common, "POSTGRES_STATEMENT_TIMEOUT_MS", 0, raising=False)
    conn = _StandIn()
    token = postgres_common.set_current_tenant("tenant-a")
    try:
        postgres_common._apply_tenant_session(conn, repeatable_read=True)  # type: ignore[arg-type]
    finally:
        postgres_common.reset_current_tenant(token)

    assert conn.pipelines == 0
    assert conn.executed == [
        ("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY", ()),
        ("SELECT set_config('app.tenant_id', %s, true)", ("tenant-a",)),
        ("SELECT set_config('app.bypass_rls', %s, true)", ("0",)),
    ]


def test_a_psycopg_connection_is_pipelined(monkeypatch: pytest.MonkeyPatch) -> None:
    psycopg = pytest.importorskip("psycopg")
    entered: list[bool] = []

    class _Pipeline:
        def __enter__(self) -> None:
            entered.append(True)

        def __exit__(self, *_exc: object) -> None:
            entered.append(False)

    conn = object.__new__(psycopg.Connection)
    monkeypatch.setattr(psycopg.Connection, "pipeline", lambda self: _Pipeline())

    with session_pipeline(conn):
        assert entered == [True]
    assert entered == [True, False]
