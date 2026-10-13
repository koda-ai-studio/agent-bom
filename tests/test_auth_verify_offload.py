"""Key verification never runs on the event loop.

``KeyStore.verify`` performs a deliberately expensive scrypt derivation (or a
blocking DB read on the Postgres store). Both surfaces below are reachable
*before* a caller is authenticated, so running verification inline lets an
unauthenticated client stall the loop on demand.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

_BLOCKING_SECONDS = 0.4
_TICK_SECONDS = 0.01
_MIN_TICKS_WHILE_OFFLOADED = 5


def _slow_key_store() -> MagicMock:
    store = MagicMock()
    store.has_keys.return_value = True

    def _slow_verify(_raw: str) -> None:
        time.sleep(_BLOCKING_SECONDS)
        return None

    store.verify.side_effect = _slow_verify
    return store


@pytest.mark.asyncio
async def test_browser_session_verify_keeps_the_loop_responsive() -> None:
    """POST /v1/auth/browser-session is auth-exempt — it must not block."""
    import httpx

    from agent_bom.api.server import app

    ticks = 0

    async def heartbeat() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(_TICK_SECONDS)
            ticks += 1

    with patch("agent_bom.api.auth.get_key_store", return_value=_slow_key_store()):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            beat = asyncio.create_task(heartbeat())
            await asyncio.sleep(_TICK_SECONDS * 2)
            before = ticks
            await client.post("/v1/auth/session", json={"api_key": "abom_whatever"})
            observed = ticks - before
            beat.cancel()

    assert observed >= _MIN_TICKS_WHILE_OFFLOADED, (
        f"event loop advanced only {observed} tick(s) during a {_BLOCKING_SECONDS}s scrypt verify — it ran inline"
    )


@pytest.mark.asyncio
async def test_websocket_handshake_verifies_off_the_loop_thread() -> None:
    """The pre-auth WebSocket handshake offloads verification too."""
    from agent_bom.api import websocket_auth as proxy

    loop_thread = threading.get_ident()
    seen: dict[str, Any] = {}

    def _record(_token: str, *, bearer: bool = True) -> None:
        seen["thread"] = threading.get_ident()
        return None

    class _FakeWebSocket:
        headers = {"authorization": "Bearer abom_whatever"}
        query_params: dict[str, str] = {}

        async def accept(self) -> None:
            return None

        async def receive_json(self) -> dict[str, Any]:
            raise asyncio.CancelledError

        async def close(self, code: int = 1000) -> None:
            return None

    with (
        patch.object(proxy, "_ws_auth_from_token", _record),
        patch.object(proxy, "_ws_auth_required", return_value=True),
        patch.object(proxy, "_ws_auth_from_trusted_proxy", return_value=None),
    ):
        try:
            await proxy._ws_accept_and_check_auth(_FakeWebSocket())  # type: ignore[arg-type]
        except (asyncio.CancelledError, Exception):
            pass

    assert seen.get("thread") is not None, "verification was never invoked"
    assert seen["thread"] != loop_thread, "key verification ran on the event loop thread"


@pytest.mark.asyncio
async def test_managed_trial_lifecycle_read_keeps_the_loop_responsive(monkeypatch: pytest.MonkeyPatch) -> None:
    """Managed-trial session validation must not block on Postgres lifecycle reads."""
    import httpx
    from fastapi import FastAPI

    from agent_bom.api.browser_session import create_browser_session_token
    from agent_bom.api.middleware import APIKeyMiddleware

    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "synthetic-signing-key-for-tests")

    def _slow_tenant_access_active(_tenant_id: str) -> bool:
        time.sleep(_BLOCKING_SECONDS)
        return True

    token, _csrf = create_browser_session_token(
        subject="oidc-subject-123",
        role="analyst",
        tenant_id="trial-example-123",
        auth_method="managed_trial_oidc",
        scopes=["finding:read"],
        max_age_seconds=3600,
    )
    app = FastAPI()

    @app.get("/v1/findings")
    async def _findings() -> dict[str, bool]:
        return {"reached": True}

    app.add_middleware(APIKeyMiddleware, api_key="")
    ticks = 0

    async def heartbeat() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(_TICK_SECONDS)
            ticks += 1

    with patch("agent_bom.api.tenant_lifecycle.tenant_access_active", _slow_tenant_access_active):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            client.cookies.set("agent_bom_session", token)
            beat = asyncio.create_task(heartbeat())
            await asyncio.sleep(_TICK_SECONDS * 2)
            before = ticks
            response = await client.get("/v1/findings")
            observed = ticks - before
            beat.cancel()

    assert response.status_code == 200
    assert observed >= _MIN_TICKS_WHILE_OFFLOADED, (
        f"event loop advanced only {observed} tick(s) during a {_BLOCKING_SECONDS}s lifecycle read — it ran inline"
    )


@pytest.mark.asyncio
async def test_disabled_scim_role_resolution_does_not_wait_for_worker(monkeypatch):
    import anyio.to_thread
    from fastapi import FastAPI
    from starlette.requests import Request

    from agent_bom.api.middleware import APIKeyMiddleware
    from agent_bom.rbac import Role

    for name in ("AGENT_BOM_SCIM_BEARER_TOKEN", "AGENT_BOM_SCIM_BEARER_TOKEN_FILE", "AGENT_BOM_SCIM_BEARER_TOKENS_JSON"):
        monkeypatch.delenv(name, raising=False)
    middleware = APIKeyMiddleware(FastAPI(), api_key="")
    limiter = anyio.to_thread.current_default_thread_limiter()
    before = limiter.total_tokens
    limiter.total_tokens = 1
    borrower = object()
    await limiter.acquire_on_behalf_of(borrower)
    try:
        result = await asyncio.wait_for(
            middleware._resolve_runtime_role(
                Request({"type": "http"}), tenant_id="tenant", upstream_role=Role.ANALYST, subjects=("subject",)
            ),
            0.5,
        )
        assert result == (Role.ANALYST, None)
    finally:
        limiter.release_on_behalf_of(borrower)
        limiter.total_tokens = before


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["AGENT_BOM_SCIM_BEARER_TOKEN", "AGENT_BOM_SCIM_BEARER_TOKEN_FILE", "AGENT_BOM_SCIM_BEARER_TOKENS_JSON"])
async def test_configured_scim_sources_recheck_revocation_off_loop(monkeypatch, source):
    from fastapi import FastAPI
    from starlette.requests import Request

    from agent_bom.api import auth
    from agent_bom.api.middleware import APIKeyMiddleware
    from agent_bom.api.postgres_common import _current_tenant, reset_current_tenant, set_current_tenant
    from agent_bom.rbac import Role

    for name in ("AGENT_BOM_SCIM_BEARER_TOKEN", "AGENT_BOM_SCIM_BEARER_TOKEN_FILE", "AGENT_BOM_SCIM_BEARER_TOKENS_JSON"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(source, "synthetic-source")
    loop_thread = threading.get_ident()
    calls = []

    def resolve(tenant, *subjects):
        assert threading.get_ident() != loop_thread
        assert tenant == _current_tenant.get() == "tenant"
        assert subjects == ("subject",)
        calls.append(tenant)
        return auth.SCIMRoleResolution(matched=True, active=len(calls) == 1, role=Role.VIEWER, user_id="subject")

    monkeypatch.setattr(auth, "resolve_scim_user_role", resolve)
    middleware = APIKeyMiddleware(FastAPI(), api_key="")
    token = set_current_tenant("tenant")
    try:
        role, error = await middleware._resolve_runtime_role(
            Request({"type": "http"}), tenant_id="tenant", upstream_role=Role.ADMIN, subjects=("subject",)
        )
        assert role == Role.VIEWER and error is None
        role, error = await middleware._resolve_runtime_role(
            Request({"type": "http"}), tenant_id="tenant", upstream_role=Role.ADMIN, subjects=("subject",)
        )
        assert role is None and error.status_code == 401
        assert len(calls) == 2
    finally:
        reset_current_tenant(token)
