"""Rejected credentials have a bounded request budget and signed failure receipts."""

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agent_bom.api import audit_log
from agent_bom.api.middleware_limits import GlobalRateLimitMiddleware


def test_bad_keys_from_eight_clients_are_limited_and_audited(monkeypatch):
    events = []
    monkeypatch.setattr(audit_log, "log_action", lambda action, **kw: events.append((action, kw)))

    async def authenticate(request):
        return JSONResponse({}, status_code=200 if request.headers.get("x-api-key") == "valid-test-key" else 401)

    app = Starlette(routes=[Route("/v1/findings", authenticate)])
    app.add_middleware(GlobalRateLimitMiddleware)
    statuses = []
    for n in range(8):
        with TestClient(app, client=(f"127.0.0.{n + 1}", 5000)) as client:
            responses = [client.get("/v1/findings", headers={"x-api-key": "invalid-test-key", "x-tenant-id": "forged"}) for _ in range(50)]
            statuses.extend(r.status_code for r in responses)
            assert any(r.status_code == 429 and int(r.headers["retry-after"]) > 0 for r in responses)

    assert statuses.count(429) > 0
    assert 0 < len(events) <= 24
    assert all(action == "auth.failed" for action, _ in events)
    assert "invalid-test-key" not in repr(events)
    assert "forged" not in repr(events)

    with TestClient(app, client=("192.0.2.200", 5000)) as client:
        assert client.get("/v1/findings", headers={"x-api-key": "valid-test-key"}).status_code == 200


def test_spoofed_forwarding_does_not_evade_source_limit(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_TRUSTED_PROXY_HOPS", raising=False)
    monkeypatch.delenv("AGENT_BOM_TRUSTED_PROXY_CIDRS", raising=False)
    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "2")
    monkeypatch.setattr(audit_log, "log_action", lambda *a, **kw: None)

    async def denied(request):
        return JSONResponse({}, status_code=401)

    app = Starlette(routes=[Route("/v1/findings", denied)])
    app.add_middleware(GlobalRateLimitMiddleware)
    with TestClient(app, client=("192.0.2.2", 1000)) as client:
        assert client.get("/v1/findings", headers={"x-forwarded-for": "198.51.100.1"}).status_code == 401
        assert client.get("/v1/findings", headers={"x-forwarded-for": "198.51.100.2"}).status_code == 429
        assert client.get("/v1/findings", headers={"x-forwarded-for": "198.51.100.3"}).status_code == 429


def test_trusted_proxy_clients_have_separate_budgets(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_TRUSTED_PROXY_HOPS", "1")
    monkeypatch.setenv("AGENT_BOM_TRUSTED_PROXY_CIDRS", "192.0.2.0/24")
    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "1")
    monkeypatch.setattr(audit_log, "log_action", lambda *a, **kw: None)

    async def authenticate(request):
        return JSONResponse({}, status_code=200 if request.headers.get("x-api-key") == "valid-test-key" else 401)

    app = Starlette(routes=[Route("/v1/findings", authenticate)])
    app.add_middleware(GlobalRateLimitMiddleware)
    with TestClient(app, client=("192.0.2.2", 1000)) as client:
        assert client.get("/v1/findings", headers={"x-forwarded-for": "198.51.100.1"}).status_code == 429
        assert client.get("/v1/findings", headers={"x-forwarded-for": "198.51.100.2", "x-api-key": "valid-test-key"}).status_code == 200


def test_auth_store_outage_fails_closed_but_probes_and_static_survive(monkeypatch):
    from agent_bom.api.auth_failure_store import SQLiteAuthFailureStore

    def unavailable(*args):
        raise RuntimeError("unavailable")

    monkeypatch.setattr(SQLiteAuthFailureStore, "remaining", unavailable)

    async def ok(request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route(path, ok) for path in ("/health", "/_next/static/app.js", "/v1/findings")])
    app.add_middleware(GlobalRateLimitMiddleware)
    with TestClient(app) as client:
        assert client.get("/v1/findings").status_code == 503
        assert client.get("/health").status_code == 200
        assert client.get("/_next/static/app.js").status_code == 200


def test_standalone_mcp_rejections_are_throttled(monkeypatch):
    from datetime import datetime, timedelta, timezone

    from agent_bom.mcp_server import create_mcp_server

    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "2")
    monkeypatch.setenv("AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT", (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
    monkeypatch.setattr(audit_log, "log_action", lambda *a, **kw: None)
    server = create_mcp_server(host="127.0.0.1", port=8000, bearer_token="test-only-mcp", profile="scan")
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000", client=("192.0.2.5", 1000)) as client:
        assert client.post("/mcp", headers={"authorization": "Bearer wrong"}).status_code == 401
        assert client.post("/mcp", headers={"authorization": "Bearer wrong"}).status_code == 429


@pytest.mark.parametrize("method", ["api_key", "browser_session", "oidc"])
def test_real_auth_resolvers_share_failure_budget_and_safe_receipts(monkeypatch, method):
    import base64
    import json

    from agent_bom.api import auth
    from agent_bom.api.auth import KeyStore
    from agent_bom.api.browser_session import SESSION_COOKIE_NAME
    from agent_bom.api.middleware import APIKeyMiddleware

    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "2")
    monkeypatch.setattr(auth, "_key_store", KeyStore())
    store = audit_log.InMemoryAuditLog()
    monkeypatch.setattr(audit_log, "_audit_log", store)

    async def secured(request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/v1/findings", secured)])
    app.add_middleware(APIKeyMiddleware, api_key="valid-test-credential", allow_unauthenticated=False)
    app.add_middleware(GlobalRateLimitMiddleware)
    headers = {"x-api-key": "invalid-test-credential"}
    if method == "browser_session":
        headers = {"cookie": f"{SESSION_COOKIE_NAME}=invalid-test-session"}
    elif method == "oidc":
        header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({"iss": "https://identity.example", "sub": "test"}).encode()).decode().rstrip("=")
        headers = {"authorization": f"Bearer {header}.{payload}.c2ln"}
    with TestClient(app, client=("192.0.2.55", 1000)) as client:
        assert client.get("/v1/findings", headers=headers).status_code == 401
        assert client.get("/v1/findings", headers=headers).status_code == 429
    entries = store.list_entries(action="auth.failed", tenant_id="default")
    assert len(entries) == 2
    assert entries[0].details["source"] == "192.0.2.55"
    assert entries[0].details["payload_sha256"]
    assert all(value not in str([entry.to_dict() for entry in entries]) for value in headers.values())


def test_mcp_launcher_preserves_transport_peer(monkeypatch):
    import uvicorn

    from agent_bom.mcp_server import create_mcp_server

    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: calls.append(kw))
    server = create_mcp_server(host="127.0.0.1", port=8000, profile="scan")
    server.run(transport="streamable-http", host="127.0.0.1", port=8000)
    assert calls[0].get("proxy_headers") is False


def test_api_launcher_preserves_transport_peer(monkeypatch, tmp_path):
    import uvicorn
    from click.testing import CliRunner

    from agent_bom.cli import main

    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: calls.append(kw))
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "api.db"))
    result = CliRunner().invoke(main, ["serve", "--no-ui"])
    assert result.exit_code == 0, result.output
    assert calls[0].get("proxy_headers") is False


def test_browser_key_exchange_receipt_hashes_body_credential(monkeypatch):
    import hashlib

    from fastapi import FastAPI

    from agent_bom.api import auth
    from agent_bom.api.auth import KeyStore
    from agent_bom.api.routes.enterprise_routes.keys import router

    monkeypatch.setattr(auth, "_key_store", KeyStore())
    monkeypatch.delenv("AGENT_BOM_API_KEY", raising=False)
    store = audit_log.InMemoryAuditLog()
    monkeypatch.setattr(audit_log, "_audit_log", store)
    app = FastAPI()
    app.include_router(router, prefix="/v1")
    app.add_middleware(GlobalRateLimitMiddleware)
    bad_key = "body-only-invalid-credential"
    with TestClient(app, client=("192.0.2.61", 1000)) as client:
        assert client.post("/v1/auth/session", json={"api_key": bad_key}).status_code == 401
    entry = store.list_entries(action="auth.failed", tenant_id="default")[0]
    assert entry.details["payload_sha256"] == hashlib.sha256(bad_key.encode()).hexdigest()
    assert bad_key not in str(entry.to_dict())


@pytest.mark.asyncio
async def test_stalled_auth_store_has_bounded_outstanding_work(monkeypatch):
    import asyncio
    import threading
    from types import SimpleNamespace

    from agent_bom.api.auth_failure_policy import AuthFailurePolicy

    policy = AuthFailurePolicy()
    gate = threading.Event()
    calls = []

    def stall(*args):
        calls.append(1)
        gate.wait(5)
        return 0

    monkeypatch.setattr(policy.store, "remaining", stall)
    request = SimpleNamespace(client=SimpleNamespace(host="192.0.2.90"), headers={})
    try:
        responses = await asyncio.gather(*(policy.before(request) for _ in range(40)))
        assert all(response.status_code == 503 for response in responses)
        assert len(calls) <= 8
    finally:
        gate.set()
        await asyncio.sleep(0.05)


@pytest.mark.asyncio
async def test_sqlite_ingest_write_lock_does_not_block_auth_budget(monkeypatch, tmp_path):
    import sqlite3
    from types import SimpleNamespace

    from agent_bom.api.auth_failure_policy import AuthFailurePolicy

    path = str(tmp_path / "jobs.db")
    monkeypatch.setenv("AGENT_BOM_DB", path)
    policy = AuthFailurePolicy()
    with sqlite3.connect(path) as writer:
        writer.execute("BEGIN IMMEDIATE")
        try:
            request = SimpleNamespace(client=SimpleNamespace(host="192.0.2.80"), headers={})
            assert await policy.before(request) is None
        finally:
            writer.rollback()


@pytest.mark.asyncio
async def test_auth_checks_do_not_queue_behind_unrelated_executor_work():
    import asyncio
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from types import SimpleNamespace

    from agent_bom.api.auth_failure_policy import AuthFailurePolicy

    loop = asyncio.get_running_loop()
    gate = threading.Event()
    started = threading.Event()
    executor = ThreadPoolExecutor(max_workers=1)
    loop.set_default_executor(executor)

    def unrelated_work():
        started.set()
        gate.wait(5)

    blocker = loop.run_in_executor(None, unrelated_work)
    policy = AuthFailurePolicy()
    request = SimpleNamespace(client=SimpleNamespace(host="192.0.2.99"), headers={})
    try:
        while not started.is_set():
            await asyncio.sleep(0)
        assert await policy.before(request) is None
    finally:
        gate.set()
        await blocker
        executor.shutdown(wait=True)
