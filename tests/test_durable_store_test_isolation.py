"""Per-test backend selection must not retain a previous temporary database."""

import importlib

import pytest

from tests.conftest import _reset_durable_store_singletons


@pytest.mark.parametrize(
    ("module_name", "getter", "setter"),
    [
        ("agent_bom.api.blueprint_store", "get_blueprint_store", "set_blueprint_store"),
        ("agent_bom.api.kspm_posture_store", "get_kspm_posture_store", "set_kspm_posture_store"),
        ("agent_bom.api.export_schedule_store", "get_export_schedule_store", "set_export_schedule_store"),
        ("agent_bom.api.export_destination_store", "get_export_destination_store", "set_export_destination_store"),
        ("agent_bom.ticketing.connection_store", "get_ticketing_store", "set_ticketing_store"),
        ("agent_bom.api.skills_scan_store", "get_skills_scan_store", "set_skills_scan_store"),
    ],
)
def test_backend_reselected_after_test_database_changes(monkeypatch, tmp_path, module_name, getter, setter):
    module = importlib.import_module(module_name)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    getattr(module, setter)(None)
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "previous.db"))
    previous = getattr(module, getter)()
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "next.db"))
    _reset_durable_store_singletons()
    try:
        assert getattr(module, getter)() is not previous
    finally:
        getattr(module, setter)(None)


def test_side_scan_state_does_not_cross_test_boundaries(monkeypatch):
    from agent_bom.cloud.side_scan_lifecycle import (
        get_side_scan_state_store,
        new_side_scan_execution,
        reset_side_scan_state_store,
    )

    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("AGENT_BOM_SIDE_SCAN_STATE_DB", raising=False)
    monkeypatch.setenv("AGENT_BOM_EPHEMERAL_STORE", "1")
    reset_side_scan_state_store()
    previous = get_side_scan_state_store()
    previous.create_or_get(
        new_side_scan_execution(
            tenant_id="test-tenant",
            provider="aws",
            account_id="test-account",
            target_id="test-target",
            collector_id="test-collector",
            idempotency_key="test-key",
        )
    )
    _reset_durable_store_singletons()
    try:
        assert get_side_scan_state_store().list_recent(tenant_id="test-tenant") == []
    finally:
        reset_side_scan_state_store()
