"""Postgres selection is one contract everywhere: AGENT_BOM_POSTGRES_URL, or its alias, a Postgres URL in AGENT_BOM_DB.

Before this test the boot gate (``preflight_storage_backends``) refused the
alias that the durable ladder, the storage tiers and every per-store adapter
honoured, so a bare-metal operator saw "SQLite requires a filesystem path"
for a configuration the rest of the control plane accepted.
"""

from __future__ import annotations

import pytest

from agent_bom.api.durable_store import postgres_configured
from agent_bom.api.storage_schema import postgres_deployment_configured
from agent_bom.storage import factory
from agent_bom.storage.factory import POSTGRES_DSN_IN_SQLITE_PATH_MESSAGE, validate_configured_sqlite_path, validate_sqlite_path
from agent_bom.storage.tiers import storage_selection_from_env

PG = "postgresql://agent_bom_app@127.0.0.1:5432/abom"


@pytest.fixture(autouse=True)
def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("AGENT_BOM_POSTGRES_URL", "AGENT_BOM_DB", "SNOWFLAKE_ACCOUNT", "AGENT_BOM_GRAPH_BACKEND"):
        monkeypatch.delenv(name, raising=False)


def test_every_selector_agrees_on_the_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_DB", PG)
    assert postgres_deployment_configured() is True
    assert postgres_configured() is True
    assert storage_selection_from_env().postgres is True
    assert factory.resolve_backend(mode="env").backend is factory.BackendKind.POSTGRES
    validate_configured_sqlite_path()  # the boot gate must not refuse what every ladder selects


def test_every_selector_agrees_on_the_canonical_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", PG)
    assert postgres_deployment_configured() is True
    assert postgres_configured() is True
    assert storage_selection_from_env().postgres is True
    validate_configured_sqlite_path()


def test_sqlite_store_openers_still_refuse_a_postgres_dsn_and_name_the_variables() -> None:
    with pytest.raises(ValueError) as excinfo:
        validate_sqlite_path(PG)
    message = str(excinfo.value)
    assert message == POSTGRES_DSN_IN_SQLITE_PATH_MESSAGE
    assert "AGENT_BOM_POSTGRES_URL" in message and "AGENT_BOM_DB" in message
    assert "agent_bom_app" not in message and "5432" not in message, "never echo the DSN"


def test_boot_still_refuses_a_dsn_no_backend_understands(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_DB", "mysql://example.invalid/abom")
    with pytest.raises(ValueError, match="AGENT_BOM_POSTGRES_URL"):
        validate_configured_sqlite_path()


def test_sqlite_paths_still_resolve(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # noqa: ANN001
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "state.db"))
    validate_configured_sqlite_path()
    selection = factory.resolve_backend(mode="env")
    assert selection.backend is factory.BackendKind.SQLITE
    assert selection.sqlite_path == str(tmp_path / "state.db")
