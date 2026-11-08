"""Regression tests for the failed-authentication control's failure modes."""

from __future__ import annotations

import asyncio
import base64
import json
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agent_bom.api import audit_log, metrics
from agent_bom.api.auth_failure_policy import AuthFailurePolicy
from agent_bom.api.auth_failure_receipts import RECEIPTS, AuthFailureReceipts
from agent_bom.api.auth_failure_store import DeadConnectionError, PostgresAuthFailureStore, SQLiteAuthFailureStore
from agent_bom.api.forwarded_identity import failure_limit_source, forwarded_for_header
from agent_bom.api.middleware_limits import GlobalRateLimitMiddleware


class OperationalError(Exception):
    """Named like the driver's connection-class error."""


def _request(host="192.0.2.1", headers=None):
    return SimpleNamespace(client=SimpleNamespace(host=host) if host else None, headers=Headers(raw=headers or []), state=SimpleNamespace())


def _failing_app(status=401, mark=True):
    async def reject(request):
        if mark:
            request.state.authentication_failed = True
        return JSONResponse({}, status_code=status)

    app = Starlette(routes=[Route("/v1/findings", reject)])
    app.add_middleware(GlobalRateLimitMiddleware)
    return app


# The event loop answers everyone


@pytest.mark.asyncio
async def test_key_store_read_does_not_hold_the_event_loop(monkeypatch):
    from agent_bom.api import auth
    from agent_bom.api.middleware import APIKeyMiddleware

    release = threading.Event()

    class SlowStore:
        def verify(self, _raw):
            release.wait(2)
            return None

    monkeypatch.setattr(auth, "_key_store", SlowStore())

    async def secured(request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/v1/findings", secured)])
    app.add_middleware(APIKeyMiddleware, api_key="", allow_unauthenticated=False)

    import httpx

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        pending = asyncio.create_task(client.get("/v1/findings", headers={"x-api-key": "wrong"}))
        started = time.monotonic()
        await asyncio.sleep(0.05)
        assert time.monotonic() - started < 0.5  # The loop kept running during the store read.
        assert not pending.done()
        release.set()
        assert (await pending).status_code == 401


# Reconnects and the outage breaker


class _StalePool:
    """Hands out dead connections first, as a pool does right after a database restart."""

    def __init__(self, stale):
        self.stale = stale
        self.rows = {}

    @contextmanager
    def connection(self, **_kwargs):
        if self.stale:
            self.stale -= 1
            raise OperationalError("server closed the connection unexpectedly")

        class Cursor:
            def fetchone(self):
                return None

        class Connection:
            def execute(self, *_args):
                return Cursor()

            @contextmanager
            def pipeline(self):
                yield

        yield Connection()


def test_stale_pooled_connections_cost_one_operation_nothing_more():
    store = PostgresAuthFailureStore.__new__(PostgresAuthFailureStore)
    store._pool = _StalePool(stale=7)
    assert store.remaining("192.0.2.1", 100) == 0
    assert store._pool.stale == 0


def test_a_persistent_connection_failure_is_still_raised():
    store = PostgresAuthFailureStore.__new__(PostgresAuthFailureStore)
    store._pool = _StalePool(stale=10_000)
    with pytest.raises(DeadConnectionError):
        store.remaining("192.0.2.1", 100)


def test_a_query_error_is_not_retried_as_a_dead_connection():
    store = PostgresAuthFailureStore.__new__(PostgresAuthFailureStore)
    calls = []

    class Pool:
        @contextmanager
        def connection(self, **_kwargs):
            calls.append(1)
            error = OperationalError("bad column")
            error.sqlstate = "42703"
            raise error
            yield

    store._pool = Pool()
    with pytest.raises(OperationalError):
        store.remaining("192.0.2.1", 100)
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_isolated_store_errors_do_not_open_the_global_breaker(monkeypatch):
    policy = AuthFailurePolicy()
    errors = {"192.0.2.1", "192.0.2.2"}

    def remaining(source, _now):
        if source in errors:
            raise OSError("one failed connection")
        return 0

    monkeypatch.setattr(policy.store, "remaining", remaining)
    assert (await policy.before(_request("192.0.2.1"))).status_code == 503
    assert (await policy.before(_request("192.0.2.2"))).status_code == 503
    assert await policy.before(_request("192.0.2.3")) is None
    assert policy._unavailable_until == 0
    assert policy._store_failures == 0


@pytest.mark.asyncio
async def test_repeated_store_errors_open_the_breaker_and_one_success_closes_it(monkeypatch):
    policy = AuthFailurePolicy()
    calls = []
    healthy = threading.Event()

    def remaining(source, _now):
        calls.append(source)
        if not healthy.is_set():
            raise OSError("store down")
        return 0

    monkeypatch.setattr(policy.store, "remaining", remaining)
    for number in range(3):
        assert (await policy.before(_request(f"192.0.2.{number + 1}"))).status_code == 503
    assert policy._unavailable_until > time.monotonic()

    # Open: requests are refused without queuing on the failed store.
    before = len(calls)
    responses = [await policy.before(_request(f"192.0.2.{number + 10}")) for number in range(20)]
    assert all(response.status_code == 503 for response in responses)
    assert len(calls) - before <= 1

    healthy.set()
    await asyncio.sleep(0.55)
    assert await policy.before(_request("192.0.2.99")) is None
    assert policy._unavailable_until == 0
    assert await policy.before(_request("192.0.2.100")) is None


# Receipts have their own capacity


def test_receipt_writes_do_not_use_authentication_capacity(monkeypatch):
    gate = threading.Event()
    started = []

    def stalled(*_args, **_kwargs):
        started.append(1)
        gate.wait(5)

    monkeypatch.setattr(audit_log, "log_action", stalled)
    app = _failing_app()
    try:
        with TestClient(app) as client:
            begun = time.monotonic()
            statuses = [
                client.get("/v1/findings", headers={"x-api-key": "wrong", "x-forwarded-for": "ignored"}).status_code for _ in range(3)
            ]
            assert statuses == [401, 401, 401]
            assert time.monotonic() - begun < 2  # A stalled audit store does not delay the answer.
            assert started
    finally:
        gate.set()
        assert RECEIPTS.flush()


@pytest.mark.asyncio
async def test_failed_logins_during_a_stalled_audit_write_do_not_refuse_others(monkeypatch):
    gate = threading.Event()
    monkeypatch.setattr(audit_log, "log_action", lambda *_a, **_k: gate.wait(5))
    policy = AuthFailurePolicy()
    try:
        for number in range(40):
            request = _request(f"198.51.100.{number + 1}")
            request.state.authentication_failed = True
            response = await policy.after(request, JSONResponse({}, status_code=401))
            assert response.status_code == 401
        assert await policy.before(_request("192.0.2.77")) is None
        assert policy._unavailable_until == 0
    finally:
        gate.set()
        assert RECEIPTS.flush()


def _reason_count(reason):
    return metrics._auth_receipts_dropped.snapshot().get(reason, 0)


def test_receipts_that_cannot_be_queued_are_counted_and_recorded_later(monkeypatch):
    gate = threading.Event()
    written = []

    def write(action, **details):
        gate.wait(5)
        written.append((action, details))

    monkeypatch.setattr(audit_log, "log_action", write)
    receipts = AuthFailureReceipts(capacity=2, per_source=1000)
    before = _reason_count("queue_full")
    allowed = lambda *_args: True  # noqa: E731
    for number in range(20):
        receipts.submit(f"198.51.100.{number}", 1.0, allowed, status_code=401)
    gate.set()
    assert receipts.flush()
    dropped = _reason_count("queue_full") - before
    assert dropped >= 1
    assert sum(1 for action, _ in written if action == "auth.failed") == 20 - dropped

    gaps = [details for action, details in written if action == "auth.receipts_dropped"]
    assert sum(gap["dropped_receipts"] for gap in gaps) == dropped
    assert all(gap["tenant_id"] == audit_log.AUTH_FAILURE_AUDIT_TENANT for gap in gaps)


def test_one_source_cannot_fill_the_receipt_queue():
    gate = threading.Event()
    receipts = AuthFailureReceipts(capacity=256, per_source=3)
    before = _reason_count("source_queue_full")
    allowed = lambda *_args: (gate.wait(5), False)[1]  # noqa: E731
    for _ in range(50):
        receipts.submit("198.51.100.1", 1.0, allowed)
    assert _reason_count("source_queue_full") - before == 47
    gate.set()
    assert receipts.flush()


def test_dropped_receipts_appear_in_the_metrics_output():
    assert "agent_bom_auth_receipts_dropped_total" in "\n".join(metrics.render_prometheus_lines())


# An audit failure stays out of authentication


@pytest.mark.asyncio
async def test_audit_write_errors_affect_neither_the_caller_nor_other_sources(monkeypatch):
    def broken(*_args, **_kwargs):
        raise RuntimeError("audit append failed")

    monkeypatch.setattr(audit_log, "log_action", broken)
    before = _reason_count("write_failed")
    policy = AuthFailurePolicy()
    for _ in range(4):
        request = _request("198.51.100.5")
        request.state.authentication_failed = True
        assert (await policy.after(request, JSONResponse({}, status_code=401))).status_code == 401
    assert RECEIPTS.flush()
    assert _reason_count("write_failed") - before >= 1
    assert policy._unavailable_until == 0
    assert policy._store_failures == 0
    assert await policy.before(_request("192.0.2.200")) is None


@pytest.mark.asyncio
async def test_audit_budget_errors_affect_neither_the_caller_nor_other_sources(monkeypatch):
    policy = AuthFailurePolicy()

    def broken(*_args):
        raise OSError("budget store failed")

    monkeypatch.setattr(policy.store, "audit_allowed", broken)
    request = _request("198.51.100.6")
    request.state.authentication_failed = True
    assert (await policy.after(request, JSONResponse({}, status_code=401))).status_code == 401
    assert RECEIPTS.flush()
    assert policy._unavailable_until == 0


def test_stalled_sqlite_transaction_blocks_no_other_source(tmp_path):
    store = SQLiteAuthFailureStore(str(tmp_path / "limits.db"))
    held, release = threading.Event(), threading.Event()

    def stall():
        with store.transaction("198.51.100.1"):
            held.set()
            release.wait(5)

    stalled = threading.Thread(target=stall)
    stalled.start()
    assert held.wait(2)
    try:
        started = time.monotonic()
        results = [store.remaining(f"192.0.2.{number}", 100) for number in range(23)]
        assert results == [0] * 23
        assert time.monotonic() - started < 0.4  # No waiting behind the stalled writer.
    finally:
        release.set()
        stalled.join()


def test_sqlite_writers_wait_a_bounded_time_on_a_stalled_writer(tmp_path):
    store = SQLiteAuthFailureStore(str(tmp_path / "limits.db"))
    held, release = threading.Event(), threading.Event()

    def stall():
        with store.transaction("198.51.100.1"):
            held.set()
            release.wait(5)

    stalled = threading.Thread(target=stall)
    stalled.start()
    assert held.wait(2)
    try:
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            store.record("192.0.2.1", 100, limit=3, base=10, maximum=60)
        assert time.monotonic() - started < 1
    finally:
        release.set()
        stalled.join()


# Only a presented credential that failed verification counts


def test_unmarked_401s_never_consume_the_budget(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "2")
    events = []
    monkeypatch.setattr(audit_log, "log_action", lambda *a, **k: events.append(a))
    with TestClient(_failing_app(mark=False), client=("192.0.2.31", 1000)) as client:
        assert {client.get("/v1/findings").status_code for _ in range(20)} == {401}
    assert RECEIPTS.flush()
    assert events == []


def _auth_app(allow_unauthenticated=False):
    from agent_bom.api.middleware import APIKeyMiddleware

    async def secured(request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/v1/findings", secured), Route("/v1/auth/me", secured)])
    app.add_middleware(APIKeyMiddleware, api_key="valid-test-credential", allow_unauthenticated=allow_unauthenticated)
    app.add_middleware(GlobalRateLimitMiddleware)
    return app


def _forge_session(payload: dict) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(b"\x00" * 32).decode().rstrip("=")
    return f"{encoded}.{signature}"


@pytest.fixture
def real_auth(monkeypatch):
    from agent_bom.api import auth
    from agent_bom.api.auth import KeyStore

    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "2")
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "s" * 48)
    monkeypatch.setattr(auth, "_key_store", KeyStore())
    monkeypatch.setattr(audit_log, "_audit_log", audit_log.InMemoryAuditLog())


def test_missing_credential_never_locks_out_a_source(real_auth):
    with TestClient(_auth_app(), client=("192.0.2.32", 1000)) as client:
        assert {client.get("/v1/auth/me").status_code for _ in range(20)} == {401}
        assert client.get("/v1/findings", headers={"x-api-key": "valid-test-credential"}).status_code == 200


def test_expired_session_never_locks_out_its_user(real_auth):
    from agent_bom.api import browser_session

    token = _expired_session()
    cookie = {"cookie": f"{browser_session.SESSION_COOKIE_NAME}={token}"}
    with TestClient(_auth_app(), client=("192.0.2.33", 1000)) as client:
        assert {client.get("/v1/findings", headers=cookie).status_code for _ in range(20)} == {401}
        assert client.get("/v1/findings", headers={"x-api-key": "valid-test-credential"}).status_code == 200


def _expired_session() -> str:
    import hashlib
    import hmac

    from agent_bom.api import browser_session

    payload = {"exp": 1, "sub": "person", "nonce": "n", "role": "viewer", "tenant_id": "default"}
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = hmac.new(browser_session._signing_key(), encoded.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"


def test_session_from_a_previous_signing_key_never_locks_out_its_user(real_auth):
    from agent_bom.api import browser_session

    token = _forge_session({"exp": int(time.time()) + 3600, "nonce": "n", "sub": "person", "role": "viewer"})
    cookie = {"cookie": f"{browser_session.SESSION_COOKIE_NAME}={token}"}
    with TestClient(_auth_app(), client=("192.0.2.34", 1000)) as client:
        assert {client.get("/v1/findings", headers=cookie).status_code for _ in range(20)} == {401}


def test_unreadable_session_cookie_counts_as_a_failed_credential(real_auth):
    from agent_bom.api import browser_session

    cookie = {"cookie": f"{browser_session.SESSION_COOKIE_NAME}=not-a-session"}
    with TestClient(_auth_app(), client=("192.0.2.35", 1000)) as client:
        assert client.get("/v1/findings", headers=cookie).status_code == 401
        assert client.get("/v1/findings", headers=cookie).status_code == 429


@pytest.mark.parametrize(
    "headers",
    [{"x-api-key": "wrong"}, {"authorization": "Bearer wrong"}, {"authorization": "Basic d3Jvbmc="}],
    ids=["api-key", "bearer", "unsupported-scheme"],
)
def test_presented_credentials_that_fail_count(real_auth, headers):
    with TestClient(_auth_app(), client=("192.0.2.36", 1000)) as client:
        assert client.get("/v1/findings", headers=headers).status_code == 401
        assert client.get("/v1/findings", headers=headers).status_code == 429


def test_unattested_proxy_identity_headers_do_not_count(real_auth):
    with TestClient(_auth_app(), client=("192.0.2.37", 1000)) as client:
        assert {client.get("/v1/findings", headers={"x-forwarded-email": "a@example.test"}).status_code for _ in range(12)} == {401}


def test_valid_key_missing_a_report_token_does_not_lock_out_its_source(real_auth):
    from fastapi import FastAPI, HTTPException, Request

    from agent_bom.api.middleware import APIKeyMiddleware

    app = FastAPI()

    @app.get("/v1/reports/{job_id}/download")
    def download(job_id: str, request: Request):
        raise HTTPException(status_code=401, detail="Missing download token")

    app.add_middleware(APIKeyMiddleware, api_key="valid-test-credential", allow_unauthenticated=False)
    app.add_middleware(GlobalRateLimitMiddleware)
    with TestClient(app, client=("192.0.2.38", 1000)) as client:
        statuses = {client.get("/v1/reports/1/download", headers={"x-api-key": "valid-test-credential"}).status_code for _ in range(12)}
    assert 429 not in statuses


def _expiring_oidc(monkeypatch, error):
    from agent_bom.api.oidc import OIDCConfig

    config = SimpleNamespace(enabled=True, verify=lambda _token: (_ for _ in ()).throw(error))
    monkeypatch.setattr(OIDCConfig, "from_env", classmethod(lambda cls: config))


@pytest.mark.parametrize("error_name", ["OIDCTokenExpiredError", "OIDCProviderUnavailableError"])
def test_expired_tokens_and_provider_outages_do_not_count(real_auth, monkeypatch, error_name):
    from agent_bom.api import oidc

    _expiring_oidc(monkeypatch, getattr(oidc, error_name)("failed"))
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"iss": "https://identity.example", "sub": "x"}).encode()).decode().rstrip("=")
    token = {"authorization": f"Bearer {header}.{payload}.c2ln"}
    with TestClient(_auth_app(), client=("192.0.2.39", 1000)) as client:
        assert {client.get("/v1/findings", headers=token).status_code for _ in range(12)} == {401}


def test_expired_jwt_is_recognised_only_after_its_signature_verifies(monkeypatch):
    """PyJWT must check the signature first, or forged expired tokens would not count."""
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    from agent_bom.api import oidc

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    claims = {"iss": "https://identity.example", "sub": "x", "iat": 1, "exp": 2, "aud": "api"}
    genuine, forged = jwt.encode(claims, key, algorithm="RS256"), jwt.encode(claims, other, algorithm="RS256")

    class Client:
        def __init__(self, *_args, **_kwargs):
            pass

        def get_signing_key_from_jwt(self, _token):
            return SimpleNamespace(key=key.public_key())

    monkeypatch.setattr(jwt, "PyJWKClient", Client)
    kwargs = {"issuer": "https://identity.example", "audience": "api", "jwks_uri": "https://identity.example/jwks"}
    monkeypatch.setattr(oidc, "_validate_jwks_uri", lambda _issuer, uri, **_kw: uri)
    with pytest.raises(oidc.OIDCTokenExpiredError):
        oidc.verify_oidc_token(genuine, **kwargs)
    with pytest.raises(oidc.OIDCError) as forged_error:
        oidc.verify_oidc_token(forged, **kwargs)
    assert forged_error.value.counts_as_failed_credential


# Forwarded lines and IPv6 grouping


def test_every_forwarded_line_is_combined_in_order():
    headers = Headers(raw=[(b"x-forwarded-for", b"203.0.113.1"), (b"x-forwarded-for", b"203.0.113.2, 203.0.113.3")])
    assert forwarded_for_header(headers) == "203.0.113.1,203.0.113.2, 203.0.113.3"
    assert forwarded_for_header({"x-forwarded-for": "203.0.113.9"}) == "203.0.113.9"
    assert forwarded_for_header({}) == ""


def test_second_forwarded_line_decides_the_source(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_TRUSTED_PROXY_HOPS", "1")
    monkeypatch.setenv("AGENT_BOM_TRUSTED_PROXY_CIDRS", "192.0.2.0/24")
    policy = AuthFailurePolicy()
    request = _request(
        "192.0.2.1",
        [(b"x-forwarded-for", b"198.51.100.200"), (b"x-forwarded-for", b"203.0.113.77")],
    )
    assert policy.source(request) == "203.0.113.77"


def test_gateway_client_address_reads_every_forwarded_line(monkeypatch):
    from agent_bom.api import gateway_request

    monkeypatch.setenv("AGENT_BOM_TRUSTED_PROXY_HOPS", "1")
    monkeypatch.setenv("AGENT_BOM_TRUSTED_PROXY_CIDRS", "192.0.2.0/24")
    request = _request("192.0.2.1", [(b"x-forwarded-for", b"198.51.100.200"), (b"x-forwarded-for", b"203.0.113.77")])
    assert gateway_request._request_source_ip(request) == "203.0.113.77"


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("2001:db8:1:2::1", "2001:db8:1:2::/64"),
        ("2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"),
        ("2001:db8:1:3::1", "2001:db8:1:3::/64"),
        ("2001:db8:1:2::1%zone-a", "2001:db8:1:2::/64"),
        ("::ffff:192.0.2.9", "192.0.2.9"),
        ("192.0.2.9", "192.0.2.9"),
        ("unknown", "unknown"),
    ],
)
def test_failure_limit_source_groups_ipv6_by_prefix(address, expected):
    assert failure_limit_source(address) == expected


def test_addresses_in_one_ipv6_prefix_share_one_budget(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "3")
    monkeypatch.setattr(audit_log, "log_action", lambda *a, **k: None)
    statuses = []
    app = _failing_app()
    for number in range(29):
        with TestClient(app, client=(f"2001:db8:1:2::{number + 1:x}", 1000)) as client:
            statuses.append(client.get("/v1/findings").status_code)
    assert statuses[:2] == [401, 401]
    assert set(statuses[2:]) == {429}
    assert RECEIPTS.flush()


def test_ipv6_receipt_keeps_the_exact_address(monkeypatch):
    store = audit_log.InMemoryAuditLog()
    monkeypatch.setattr(audit_log, "_audit_log", store)
    with TestClient(_failing_app(), client=("2001:db8:1:2::7", 1000)) as client:
        assert client.get("/v1/findings").status_code == 401
    assert RECEIPTS.flush()
    entry = store.list_entries(action="auth.failed", tenant_id=audit_log.AUTH_FAILURE_AUDIT_TENANT)[0]
    assert entry.details["source"] == "2001:db8:1:2::/64"
    assert entry.details["client_address"] == "2001:db8:1:2::7"


def test_recorded_gap_survives_audit_redaction(monkeypatch):
    store = audit_log.InMemoryAuditLog()
    monkeypatch.setattr(audit_log, "_audit_log", store)
    receipts = AuthFailureReceipts()
    for _ in range(7):
        receipts._dropped("write_failed", source="198.51.100.1", observed_at=1.0)
    assert receipts.flush()
    gap = store.list_entries(action="auth.receipts_dropped", tenant_id=audit_log.AUTH_FAILURE_AUDIT_TENANT)[0]
    assert gap.details["dropped_receipts"] == 7


# Warnings about source identity


def test_peer_outside_trusted_networks_warns_once_without_contents(monkeypatch, caplog):
    monkeypatch.setenv("AGENT_BOM_TRUSTED_PROXY_HOPS", "1")
    monkeypatch.setenv("AGENT_BOM_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    policy = AuthFailurePolicy()
    request = _request("192.0.2.1", [(b"x-forwarded-for", b"caller-controlled-value")])
    for _ in range(3):
        assert policy.source(request) == "192.0.2.1"
    assert caplog.text.count("outside AGENT_BOM_TRUSTED_PROXY_CIDRS") == 1
    assert "caller-controlled-value" not in caplog.text


def test_real_ip_only_warns_once_without_contents(monkeypatch, caplog):
    policy = AuthFailurePolicy()
    request = _request("192.0.2.1", [(b"x-real-ip", b"caller-controlled-value")])
    for _ in range(3):
        assert policy.source(request) == "192.0.2.1"
    assert caplog.text.count("X-Real-IP") >= 1
    assert sum("carried X-Real-IP" in record.getMessage() for record in caplog.records) == 1
    assert "caller-controlled-value" not in caplog.text


def test_unix_socket_warns_once(monkeypatch, caplog):
    policy = AuthFailurePolicy()
    request = _request(None)
    for _ in range(3):
        assert policy.source(request) == "unknown"
    assert sum("unix socket" in record.getMessage() for record in caplog.records) == 1


def test_configured_proxy_produces_no_source_warning(monkeypatch, caplog):
    monkeypatch.setenv("AGENT_BOM_TRUSTED_PROXY_HOPS", "1")
    monkeypatch.setenv("AGENT_BOM_TRUSTED_PROXY_CIDRS", "192.0.2.0/24")
    policy = AuthFailurePolicy()
    assert policy.source(_request("192.0.2.1", [(b"x-forwarded-for", b"203.0.113.1")])) == "203.0.113.1"
    assert "AGENT_BOM_TRUSTED_PROXY" not in caplog.text


# Capacity refusals still count the attempt


@pytest.mark.asyncio
async def test_attempts_refused_for_capacity_are_still_counted(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "10")
    monkeypatch.setattr(audit_log, "log_action", lambda *a, **k: None)
    policy = AuthFailurePolicy()
    source = "198.51.100.9"
    gate = threading.Event()
    record = policy.store.record

    def slow_record(*args, **kwargs):
        gate.wait(0.2)
        return record(*args, **kwargs)

    monkeypatch.setattr(policy.store, "record", slow_record)

    async def attempt():
        request = _request(source)
        request.state.authentication_failed = True
        return (await policy.after(request, JSONResponse({}, status_code=401))).status_code

    statuses = await asyncio.gather(*(attempt() for _ in range(40)))
    assert set(statuses) <= {401, 429}  # Refused, whether or not the count could be written yet.
    await asyncio.sleep(0.5)
    gate.set()
    assert policy._source_work == {}
    # The next admission writes what capacity deferred, and refuses the source.
    assert (await policy.before(_request(source))).status_code == 429
    assert not policy._pending_failures
    assert RECEIPTS.flush()


@pytest.mark.asyncio
async def test_failed_write_keeps_the_count_for_the_next_attempt(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "3")
    monkeypatch.setattr(audit_log, "log_action", lambda *a, **k: None)
    policy = AuthFailurePolicy()
    record, broken = policy.store.record, {"on": True}

    def flaky(*args, **kwargs):
        if broken["on"]:
            raise OSError("write failed")
        return record(*args, **kwargs)

    monkeypatch.setattr(policy.store, "record", flaky)
    request = _request("198.51.100.10")
    request.state.authentication_failed = True
    for _ in range(2):
        assert (await policy.after(request, JSONResponse({}, status_code=401))).status_code == 401
    assert policy._pending_failures["198.51.100.10"] == 2
    # Admission cannot read through the failing write, so it fails closed.
    assert (await policy.before(request)).status_code == 503
    broken["on"] = False
    assert (await policy.after(request, JSONResponse({}, status_code=401))).status_code == 429
    assert RECEIPTS.flush()


def test_record_adds_the_whole_count_atomically(tmp_path):
    store = SQLiteAuthFailureStore(str(tmp_path / "limits.db"))
    assert store.record("192.0.2.1", 100, limit=5, base=30, maximum=60, count=4) == 0
    assert store.record("192.0.2.1", 101, limit=5, base=30, maximum=60, count=1) == 30


# Public documents and outages


@pytest.mark.parametrize("path", ["/", "/version", "/docs", "/redoc", "/openapi.json", "/health"])
def test_public_documents_answer_during_outage_and_backoff(monkeypatch, path):
    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "1")
    monkeypatch.setattr(audit_log, "log_action", lambda *a, **k: None)

    async def ok(request):
        return JSONResponse({"ok": True})

    async def reject(request):
        request.state.authentication_failed = True
        return JSONResponse({}, status_code=401)

    app = Starlette(routes=[Route(path, ok), Route("/v1/findings", reject)])
    app.add_middleware(GlobalRateLimitMiddleware)
    with TestClient(app, client=("192.0.2.91", 1000)) as client:
        assert client.get("/v1/findings").status_code == 429
        assert client.get(path).status_code == 200

    def unavailable(*_args):
        raise OSError("store down")

    monkeypatch.setattr(SQLiteAuthFailureStore, "remaining", unavailable)
    with TestClient(app, client=("192.0.2.92", 1000)) as client:
        assert client.get(path).status_code == 200
        assert client.get("/v1/findings").status_code == 503


@pytest.mark.parametrize(
    ("path", "method"), [("/v1/auth/oidc/callback", "GET"), ("/v1/auth/session", "POST"), ("/v1/findings", "GET"), ("/docs", "POST")]
)
def test_routes_that_verify_credentials_keep_the_auth_state_check(path, method):
    from agent_bom.api.middleware_limits import RateLimitMiddleware

    assert not RateLimitMiddleware.needs_no_auth_state(path, method)


def test_failed_usage_timestamp_does_not_fail_a_verified_key(monkeypatch, tmp_path):
    import sqlite3

    from agent_bom.api.auth import ApiKey, Role, create_api_key
    from agent_bom.api.sqlite_key_store import SQLiteKeyStore

    store = SQLiteKeyStore(str(tmp_path / "keys.db"))
    raw, key = create_api_key("person", Role.VIEWER)
    assert isinstance(key, ApiKey)
    store.add(key)
    real = store._conn

    class DiskFull:
        def execute(self, sql, *args):
            if sql.startswith("UPDATE api_keys SET last_used"):
                error = sqlite3.OperationalError("database or disk is full")
                error.sqlite_errorcode = sqlite3.SQLITE_FULL
                raise error
            return real.execute(sql, *args)

        def __getattr__(self, name):
            return getattr(real, name)

    monkeypatch.setattr(SQLiteKeyStore, "_conn", property(lambda _self: DiskFull()))
    assert store.verify(raw).key_id == key.key_id


def test_static_key_request_does_not_verify_again_for_its_rate_limit_bucket(monkeypatch):
    from agent_bom.api import auth
    from agent_bom.api.middleware import APIKeyMiddleware
    from agent_bom.api.middleware_limits import RateLimitMiddleware

    class NoVerify:
        def has_keys(self):
            return False

        def verify(self, _raw):
            raise AssertionError("verified a second time")

    monkeypatch.setattr(auth, "_key_store", NoVerify())

    async def secured(request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/v1/findings", secured)])
    app.add_middleware(RateLimitMiddleware, get_key_store=NoVerify)
    app.add_middleware(APIKeyMiddleware, api_key="valid-test-credential", allow_unauthenticated=False)
    with TestClient(app) as client:
        assert client.get("/v1/findings", headers={"x-api-key": "valid-test-credential"}).status_code == 200


def test_a_failed_bounded_read_rolls_back_and_raises():
    from agent_bom.api.rate_limit_store import bounded_round_trip

    sent = []

    class CanceledError(Exception):
        sqlstate = "57014"

    class Connection:
        def execute(self, sql, parameters=None):
            sent.append(sql)

        @contextmanager
        def pipeline(self):
            yield
            raise CanceledError()

    with pytest.raises(CanceledError):
        bounded_round_trip(Connection(), [("SELECT pg_sleep(%s)", (1,))])
    # The connection returns to the pool outside any transaction.
    assert sent[-1] == "ROLLBACK"


def test_concurrent_sqlite_failure_writes_queue_instead_of_starving(tmp_path):
    # Ten writers, each holding the sidecar for 35 ms, need 350 ms in all. SQLite's
    # busy handler polls with growing sleeps, so without a local queue a writer can keep
    # losing until its 400 ms bound and a wrong key is answered 503 instead of 401.
    store = SQLiteAuthFailureStore(str(tmp_path / "limits.db"))
    refused = []
    start = threading.Barrier(10)

    def write(number: int) -> None:
        start.wait()
        try:
            with store.transaction(f"192.0.2.{number}") as execute:
                execute("SELECT 1", ())
                time.sleep(0.035)
        except TimeoutError:
            refused.append(number)

    for _ in range(2):
        threads = [threading.Thread(target=write, args=(n,)) for n in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    assert refused == []
