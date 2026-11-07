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
    entries = store.list_entries(action="auth.failed", tenant_id=audit_log.AUTH_FAILURE_AUDIT_TENANT)
    assert len(entries) == 2
    assert entries[0].details["source"] == "192.0.2.55"
    assert entries[0].details["hmac_sha256"]
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
    import hmac

    from fastapi import FastAPI

    from agent_bom.api import auth
    from agent_bom.api.auth import KeyStore
    from agent_bom.api.routes.enterprise_routes.keys import router

    monkeypatch.setattr(auth, "_key_store", KeyStore())
    monkeypatch.setattr(audit_log, "_HMAC_KEY", b"audit-fingerprint-test-key")
    monkeypatch.delenv("AGENT_BOM_API_KEY", raising=False)
    store = audit_log.InMemoryAuditLog()
    monkeypatch.setattr(audit_log, "_audit_log", store)
    app = FastAPI()
    app.include_router(router, prefix="/v1")
    app.add_middleware(GlobalRateLimitMiddleware)
    bad_key = "body-only-invalid-credential"
    with TestClient(app, client=("192.0.2.61", 1000)) as client:
        assert client.post("/v1/auth/session", json={"api_key": bad_key}).status_code == 401
    entry = store.list_entries(action="auth.failed", tenant_id=audit_log.AUTH_FAILURE_AUDIT_TENANT)[0]
    assert (
        entry.details["hmac_sha256"]
        == hmac.digest(b"audit-fingerprint-test-key", b"auth-failure-credential\x00" + bad_key.encode(), "sha256").hex()
    )
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
        assert await blocker is None
        executor.shutdown(wait=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("store_delay", [0, 0.65])
async def test_completed_auth_check_is_not_an_outage_when_loop_delivery_is_delayed(monkeypatch, store_delay):
    import asyncio
    import time
    from types import SimpleNamespace

    from agent_bom.api.auth_failure_policy import AuthFailurePolicy

    loop = asyncio.get_running_loop()
    policy = AuthFailurePolicy()

    def completed_check(*_args):
        # The store finishes before its deadline; an unrelated callback delays
        # delivery of the result. That must not open the outage circuit.
        loop.call_soon_threadsafe(time.sleep, 0.65)
        time.sleep(store_delay)
        return 0

    monkeypatch.setattr(policy.store, "remaining", completed_check)
    request = SimpleNamespace(client=SimpleNamespace(host="192.0.2.98"), headers={})
    response = await policy.before(request)
    if store_delay:
        assert response.status_code == 503
        assert policy._unavailable_until == 0  # A slow operation is not a global outage.
    else:
        assert response is None
        assert policy._unavailable_until == 0


@pytest.mark.asyncio
async def test_concurrent_cold_requests_share_one_source_admission_read(monkeypatch):
    import asyncio
    import time
    from types import SimpleNamespace

    from agent_bom.api.auth_failure_policy import AuthFailurePolicy

    policy = AuthFailurePolicy()
    calls = []

    def remaining(source, _now):
        calls.append(source)
        time.sleep(0.02)
        return 0

    monkeypatch.setattr(policy.store, "remaining", remaining)
    request = SimpleNamespace(client=SimpleNamespace(host="192.0.2.15"), headers={})
    responses = await asyncio.gather(*(policy.before(request) for _ in range(8)))
    assert responses == [None] * 8
    assert calls == ["192.0.2.15"]


@pytest.mark.asyncio
async def test_shared_admission_bounds_waiters_and_survives_a_cancelled_request(monkeypatch):
    import asyncio
    import threading
    from types import SimpleNamespace

    from agent_bom.api.auth_failure_policy import AuthFailurePolicy

    policy = AuthFailurePolicy()
    started, release = asyncio.Event(), threading.Event()
    loop = asyncio.get_running_loop()

    def remaining(_source, _now):
        loop.call_soon_threadsafe(started.set)
        release.wait(1)
        return 0

    monkeypatch.setattr(policy.store, "remaining", remaining)
    request = SimpleNamespace(client=SimpleNamespace(host="192.0.2.16"), headers={})
    requests = [asyncio.create_task(policy.before(request)) for _ in range(65)]
    try:
        await started.wait()
        assert requests[-1].result().status_code == 503
        requests[0].cancel()
        with pytest.raises(asyncio.CancelledError):
            assert await requests[0] is None
        release.set()
        assert await asyncio.gather(*requests[1:64]) == [None] * 63
        assert not policy._source_waiters
        assert policy._unavailable_until == 0
    finally:
        release.set()
        await asyncio.gather(*requests, return_exceptions=True)


@pytest.mark.asyncio
async def test_one_source_cannot_exhaust_auth_workers_or_open_global_breaker(monkeypatch):
    import asyncio
    import time
    from types import SimpleNamespace

    from agent_bom.api.auth_failure_policy import AuthFailurePolicy

    policy = AuthFailurePolicy()
    calls = []

    def remaining(source, _now):
        calls.append(source)
        if source == "192.0.2.11":
            time.sleep(1.2)
        return 0

    monkeypatch.setattr(policy.store, "remaining", remaining)

    def request(source):
        return SimpleNamespace(client=SimpleNamespace(host=source), headers={})

    assert await policy.before(request("192.0.2.12")) is None
    flood = [asyncio.create_task(policy.before(request("192.0.2.11"))) for _ in range(12)]
    await asyncio.sleep(0)
    try:
        assert await policy.before(request("192.0.2.12")) is None
        assert await policy.before(request("192.0.2.13")) is None
        assert all(response.status_code == 503 for response in await asyncio.gather(*flood))
        assert policy._unavailable_until == 0
        assert calls.count("192.0.2.11") <= 2
        assert calls.count("192.0.2.12") == 1  # Bounded local cache answers the warm source.
        assert await policy.before(request("192.0.2.14")) is None
    finally:
        await asyncio.gather(*flood)
        await asyncio.sleep(1.25)


@pytest.mark.parametrize("status", [400, 403])
def test_cookie_validation_errors_never_consume_auth_failure_budget(monkeypatch, status):
    events = []
    monkeypatch.setattr(audit_log, "log_action", lambda *args, **kwargs: events.append(args))

    async def validate(request):
        return JSONResponse({"detail": "Invalid filter"}, status_code=status)

    app = Starlette(routes=[Route("/v1/findings", validate)])
    app.add_middleware(GlobalRateLimitMiddleware)
    with TestClient(app, client=("192.0.2.73", 1000)) as client:
        for _ in range(12):
            assert client.get("/v1/findings", headers={"cookie": "session=present"}).status_code == status
    assert events == []


def test_failed_auth_receipts_are_not_visible_to_default_tenant_readers(monkeypatch):
    from types import SimpleNamespace

    from agent_bom.api.routes.enterprise_routes.governance import list_audit_entries

    store = audit_log.InMemoryAuditLog()
    monkeypatch.setattr(audit_log, "_audit_log", store)

    async def reject(request):
        return JSONResponse({}, status_code=401)

    app = Starlette(routes=[Route("/v1/findings", reject)])
    app.add_middleware(GlobalRateLimitMiddleware)
    with TestClient(app, client=("192.0.2.75", 1000)) as client:
        assert client.get("/v1/findings", headers={"x-api-key": "mistyped-credential"}).status_code == 401
    assert store.count(action="auth.failed") == 1
    result = list_audit_entries(SimpleNamespace(state=SimpleNamespace(tenant_id="default")))
    assert result["total"] == 0
    assert result["entries"] == []


@pytest.mark.parametrize("operation", ["list_audit_entries", "audit_integrity", "export_audit_entries"])
def test_operator_auth_chain_cannot_be_selected_through_tenant_audit_routes(operation):
    from types import SimpleNamespace

    from fastapi import HTTPException

    from agent_bom.api.routes.enterprise_routes import governance

    request = SimpleNamespace(state=SimpleNamespace(tenant_id="__auth_security__"))
    with pytest.raises(HTTPException) as error:
        getattr(governance, operation)(request)
    assert error.value.status_code == 403


def test_proxy_auth_without_source_trust_warns_at_startup(monkeypatch, caplog):
    from agent_bom.api.auth_failure_policy import AuthFailurePolicy

    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.delenv("AGENT_BOM_TRUSTED_PROXY_CIDRS", raising=False)
    monkeypatch.delenv("AGENT_BOM_TRUSTED_PROXY_HOPS", raising=False)
    AuthFailurePolicy()
    assert "valid credentials" in caplog.text
    assert "AGENT_BOM_TRUSTED_PROXY_CIDRS" in caplog.text


def test_ignored_forwarding_warns_once_without_logging_header_contents(monkeypatch, caplog):
    from types import SimpleNamespace

    from agent_bom.api.auth_failure_policy import AuthFailurePolicy

    monkeypatch.delenv("AGENT_BOM_TRUST_PROXY_AUTH", raising=False)
    monkeypatch.delenv("AGENT_BOM_TRUSTED_PROXY_CIDRS", raising=False)
    monkeypatch.delenv("AGENT_BOM_TRUSTED_PROXY_HOPS", raising=False)
    policy = AuthFailurePolicy()
    request = SimpleNamespace(client=SimpleNamespace(host="192.0.2.70"), headers={"x-forwarded-for": "untrusted-header-content"})
    for _ in range(3):
        assert policy.source(request) == "192.0.2.70"
    assert caplog.text.count("Forwarded client addresses are ignored") == 1
    assert "untrusted-header-content" not in caplog.text


def test_credential_fingerprints_change_on_key_rotation_without_exposing_guesses(monkeypatch):
    import hashlib

    credential = "mistyped-credential"
    monkeypatch.setattr(audit_log, "_HMAC_KEY", b"first-fingerprint-key")
    first = audit_log.fingerprint_auth_credential(credential)
    assert first != hashlib.sha256(credential.encode()).hexdigest()
    assert first != audit_log.sign_export_payload(credential.encode())
    monkeypatch.setattr(audit_log, "_HMAC_KEY", b"second-fingerprint-key")
    assert first != audit_log.fingerprint_auth_credential(credential)


@pytest.mark.asyncio
async def test_auth_admission_cache_is_bounded_and_refreshes_shared_backoff(monkeypatch, tmp_path):
    import asyncio
    from types import SimpleNamespace

    from agent_bom.api.auth_failure_policy import AuthFailurePolicy

    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "shared.db"))
    first, second = AuthFailurePolicy(), AuthFailurePolicy()
    request = SimpleNamespace(client=SimpleNamespace(host="192.0.2.81"), headers={})
    assert await first.before(request) is None
    # Use a real shared-store write at current wall time, after the cache was populated.
    import time

    second.store.record("192.0.2.81", time.time(), limit=1, base=30, maximum=30)
    await asyncio.sleep(1.05)
    assert (await first.before(request)).status_code == 429
    monkeypatch.setattr(first.store, "remaining", lambda *_args: 0)
    for index in range(4100):
        request.client.host = f"198.18.{index // 256}.{index % 256}"
        assert await first.before(request) is None
    assert len(first._source_cache) <= 4096


@pytest.mark.asyncio
async def test_expired_cached_admission_fails_closed_on_real_store_outage(monkeypatch):
    import asyncio
    from types import SimpleNamespace

    from agent_bom.api.auth_failure_policy import AuthFailurePolicy

    policy = AuthFailurePolicy()
    request = SimpleNamespace(client=SimpleNamespace(host="192.0.2.82"), headers={})
    assert await policy.before(request) is None

    def outage(*_args):
        raise OSError("synthetic store outage")

    monkeypatch.setattr(policy.store, "remaining", outage)
    await asyncio.sleep(1.05)
    assert (await policy.before(request)).status_code == 503
    assert not policy._source_cache
    assert policy._unavailable_until > 0


def test_oauth_token_validation_is_not_auth_failure_but_invalid_grant_is(monkeypatch):
    from fastapi import FastAPI

    from agent_bom.api.oauth_as import OAuthAuthorizationServer, build_oauth_as_router

    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "2")
    store = audit_log.InMemoryAuditLog()
    monkeypatch.setattr(audit_log, "_audit_log", store)
    server = OAuthAuthorizationServer(issuer="https://identity.example")
    registered = server.register_client({"redirect_uris": ["https://client.example/callback"]})
    app = FastAPI()
    app.include_router(build_oauth_as_router(server))
    app.add_middleware(GlobalRateLimitMiddleware)
    with TestClient(app, client=("192.0.2.83", 1000)) as client:
        for _ in range(12):
            assert client.post("/oauth/token", data={"grant_type": "unsupported"}).status_code == 400
        bad_grant = {"grant_type": "authorization_code", "client_id": registered["client_id"], "code": "expired-code"}
        assert client.post("/oauth/token", data=bad_grant).status_code == 400
        assert client.post("/oauth/token", data=bad_grant).status_code == 429
    entries = store.list_entries(action="auth.failed", tenant_id=audit_log.AUTH_FAILURE_AUDIT_TENANT)
    assert len(entries) == 2
    assert entries[0].details["hmac_sha256"] == audit_log.fingerprint_auth_credential("expired-code")
    assert "expired-code" not in str([entry.to_dict() for entry in entries])


def test_source_admission_supports_concurrent_event_loops(monkeypatch):
    import asyncio
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from types import SimpleNamespace

    from agent_bom.api.auth_failure_policy import AuthFailurePolicy

    policy = AuthFailurePolicy()
    started, release = threading.Event(), threading.Event()
    request = SimpleNamespace(client=SimpleNamespace(host="192.0.2.17"), headers={})

    def remaining(_source, _now):
        started.set()
        assert release.wait(2)
        return 0

    monkeypatch.setattr(policy.store, "remaining", remaining)

    def second_loop():
        async def check():
            task = asyncio.create_task(policy.before(request))
            await asyncio.sleep(0)
            release.set()
            return await task

        return asyncio.run(check())

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(lambda: asyncio.run(policy.before(request)))
        try:
            assert started.wait(2)
            second = pool.submit(second_loop)
            assert second.result(timeout=3) is None
            assert first.result(timeout=3) is None
            assert policy._unavailable_until == 0
        finally:
            release.set()
