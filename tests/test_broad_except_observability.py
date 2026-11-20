"""Best-effort fallbacks stay best-effort but no longer fail silently."""

from __future__ import annotations

import logging

import pytest


def test_distributed_scan_gate_logs_when_cluster_check_fails(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    from agent_bom.api import scan_queue
    from agent_bom.api.storage import deployment

    monkeypatch.delenv("AGENT_BOM_DISTRIBUTED_SCANS", raising=False)
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://fixture.invalid/db")

    def boom() -> bool:
        raise RuntimeError("fixture-private-detail")

    monkeypatch.setattr(deployment, "clustered_control_plane_required", boom)
    with caplog.at_level(logging.WARNING, logger=scan_queue.__name__):
        assert scan_queue.distributed_scans_enabled() is False
    assert "Clustered control-plane requirement check failed" in caplog.text
    assert "RuntimeError" in caplog.text
    assert "fixture-private-detail" not in caplog.text


def test_mcp_config_connection_listing_failure_is_logged(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    from agent_bom.api import connection_store
    from agent_bom.api.routes import mcp_config

    def boom() -> object:
        raise RuntimeError("fixture-private-detail")

    monkeypatch.setattr(connection_store, "get_connection_store", boom)
    with caplog.at_level(logging.WARNING, logger=mcp_config.__name__):
        assert mcp_config._tenant_connections("tenant-a") == []
    assert "Cloud connection listing failed" in caplog.text
    assert "fixture-private-detail" not in caplog.text
