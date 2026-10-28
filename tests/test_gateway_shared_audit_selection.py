"""Shared audit mode is explicit and never silently falls back to local files."""

import pytest

from agent_bom.runtime.gateway_audit import build_control_plane_audit_sink


def test_invalid_shared_audit_backend_fails_closed(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_GATEWAY_AUDIT_BACKEND", "misspelled-postgres")
    with pytest.raises(ValueError, match="audit backend"):
        build_control_plane_audit_sink("https://control.example", "placeholder", tenant_id="tenant-a")


def test_shared_audit_never_falls_back_without_postgres(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_GATEWAY_AUDIT_BACKEND", "postgres")
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    with pytest.raises(ValueError, match="Postgres"):
        build_control_plane_audit_sink("https://control.example", "placeholder", tenant_id="tenant-a")


def test_shared_mode_without_remote_sink_refuses_gateway_start(monkeypatch):
    from agent_bom.gateway_server import GatewaySettings, create_gateway_app
    from agent_bom.gateway_upstreams import UpstreamRegistry

    monkeypatch.setenv("AGENT_BOM_GATEWAY_AUDIT_BACKEND", "postgres")
    with pytest.raises(ValueError, match="control-plane audit sink"):
        create_gateway_app(GatewaySettings(registry=UpstreamRegistry([]), policy={}))
