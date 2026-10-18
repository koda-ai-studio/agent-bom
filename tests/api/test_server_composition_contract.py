"""Characterize server composition before moving its infrastructure helpers."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from fastapi.routing import APIRoute, iter_route_contexts

_FIXTURE = Path(__file__).parents[1] / "fixtures" / "server-route-contract.json"


def test_route_registration_preserves_order_methods_and_response_models() -> None:
    from agent_bom.api.server import app

    routes = [
        {
            "path": route.path,
            "methods": sorted(route.methods or ()),
            "name": route.name,
            "schema": route.include_in_schema,
            "response_model": str(route.response_model),
        }
        for route in iter_route_contexts(app.routes)
        if isinstance(route.original_route, APIRoute) and route.path != "/{path:path}"
    ]
    contract = {
        "route_count": len(routes),
        "sha256": hashlib.sha256(json.dumps(routes, sort_keys=True).encode()).hexdigest(),
    }
    if os.environ.get("AGENT_BOM_UPDATE_SERVER_GOLDENS") == "1":
        _FIXTURE.write_text(json.dumps(contract, indent=2) + "\n")
    assert contract == json.loads(_FIXTURE.read_text())


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["storage", "rls"])
async def test_startup_guards_fail_closed_before_serving(monkeypatch, failure: str) -> None:
    from agent_bom.api import server

    calls: list[str] = []

    def record(name: str):
        def check() -> None:
            calls.append(name)
            if name == failure:
                raise RuntimeError("startup guard rejected configuration")

        return check

    monkeypatch.setattr(server, "preflight_storage_backends", record("storage"))
    monkeypatch.setattr(server._state_home, "activate_demo_state_dir", record("demo"))
    monkeypatch.setattr(server, "_log_control_plane_auth_posture", record("auth"))
    monkeypatch.setattr(server._host_guard, "log_host_policy", record("host"))
    monkeypatch.setattr(server, "warn_if_ephemeral_hmac_key", record("hmac"))
    monkeypatch.setattr(server, "_apply_worker_thread_limit", record("workers"))
    monkeypatch.setattr(server, "configure_otel_tracing", record("tracing"))
    monkeypatch.setattr(server, "_preflight_postgres_tenant_isolation", record("rls"))
    monkeypatch.setattr(server, "_validate_configured_registries", record("registries"))

    with pytest.raises(RuntimeError, match="startup guard rejected"):
        async with server._lifespan(server.app):
            pytest.fail("startup failure must not admit requests")

    expected = ["storage", "demo", "auth", "host", "hmac", "workers", "tracing", "rls"]
    assert calls == expected[: expected.index(failure) + 1]
