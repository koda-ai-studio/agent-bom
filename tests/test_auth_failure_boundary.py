"""No route verifies a credential outside the failure limit, and failures stay visible."""

from __future__ import annotations

import asyncio
import re
import sqlite3
import threading
import time
from types import SimpleNamespace
from urllib.error import HTTPError, URLError

import pytest
from fastapi import FastAPI
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agent_bom.api import audit_log, metrics
from agent_bom.api.auth_failure_policy import AuthFailureMiddleware, AuthFailurePolicy
from agent_bom.api.auth_failure_receipts import AuthFailureReceipts
from agent_bom.api.auth_failure_store import SQLiteAuthFailureStore
from agent_bom.api.forwarded_identity import resolve_forwarded_client_ip
from agent_bom.api.middleware import APIKeyMiddleware
from agent_bom.api.middleware_limits import GlobalRateLimitMiddleware

_RIGHT = "valid-boundary-credential"
_WRONG = "wrong-boundary-credential"
_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
_EXTRA_PATHS = (
    "/.well-known/x",
    "/.well-known/oauth-protected-resource",
    "/health",
    "/healthz",
    "/livez",
    "/readyz",
    "/ping",
    "/version",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/",
    "/metrics",
    "/_next/static/x.js",
    "/favicon.ico",
    "/robots.txt",
    "/brand/mark.svg",
    "/findings",
    "/v1/no-such-route",
)


def _request(host="192.0.2.1", headers=None):
    return SimpleNamespace(client=SimpleNamespace(host=host), headers=Headers(raw=headers or []), state=SimpleNamespace())


@pytest.fixture
def isolated_auth(monkeypatch, tmp_path):
    from agent_bom.api import auth
    from agent_bom.api.auth import KeyStore

    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "1")
    monkeypatch.setenv("AGENT_BOM_AUTH_BACKOFF_SECONDS", "3600")
    monkeypatch.setenv("AGENT_BOM_AUTH_MAX_BACKOFF_SECONDS", "3600")
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "s" * 48)
    monkeypatch.setattr(auth, "_key_store", KeyStore())
    monkeypatch.setattr(audit_log, "_audit_log", audit_log.InMemoryAuditLog())


def _real_routes_app() -> FastAPI:
    from agent_bom.api import server as api_server

    app = FastAPI()
    app.router.routes.extend(api_server.app.routes)
    app.add_middleware(APIKeyMiddleware, api_key=_RIGHT, allow_unauthenticated=False)
    app.add_middleware(GlobalRateLimitMiddleware, rpm=300_000)
    return app


def _probes(app: FastAPI) -> list[tuple[str, str]]:
    from agent_bom.api import server as api_server

    probes = set()
    for template, operations in api_server.app.openapi()["paths"].items():
        path = re.sub(r"\{[^}]+\}", "x", template)
        for method in {*(name.upper() for name in operations), "OPTIONS", "POST", "GET"}:
            probes.add((method, path))
    for path in _EXTRA_PATHS:
        for method in _METHODS:
            probes.add((method, path))
    return sorted(probes)


def test_every_route_answers_alike_for_right_and_wrong_keys_while_blocked(isolated_auth):
    """A block leaves nothing to learn: no operation may verify a key outside the limit."""
    app = _real_routes_app()
    leaks = []
    probes = _probes(app)
    assert len(probes) > 500
    with TestClient(app, client=("192.0.2.150", 1000), raise_server_exceptions=False) as client:
        assert client.get("/v1/findings", headers={"x-api-key": _WRONG}).status_code == 429
        for method, path in probes:
            wrong = client.request(method, path, headers={"x-api-key": _WRONG}).status_code
            right = client.request(method, path, headers={"x-api-key": _RIGHT}).status_code
            if wrong != right or wrong == 401:
                leaks.append((method, path, wrong, right))
    assert leaks == []


@pytest.mark.parametrize(
    ("method", "path"), [("GET", "/.well-known/x"), ("HEAD", "/.well-known/x"), ("POST", "/health"), ("OPTIONS", "/v1/auth/me")]
)
def test_operations_that_verify_keys_cannot_be_used_for_unlimited_guessing(isolated_auth, monkeypatch, method, path):
    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "3")

    async def secured(request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/v1/findings", secured)])
    app.add_middleware(APIKeyMiddleware, api_key=_RIGHT, allow_unauthenticated=False)
    app.add_middleware(GlobalRateLimitMiddleware, rpm=300_000)
    with TestClient(app, client=("192.0.2.151", 1000), raise_server_exceptions=False) as client:
        statuses = [client.request(method, path, headers={"x-api-key": _WRONG}).status_code for _ in range(40)]
    assert 429 in statuses
    assert statuses.count(401) < 4


def test_cors_preflight_is_still_answered_during_a_block(isolated_auth):
    app = _real_routes_app()
    preflight = {"origin": "https://ui.example", "access-control-request-method": "GET"}
    with TestClient(app, client=("192.0.2.152", 1000), raise_server_exceptions=False) as client:
        assert client.get("/v1/findings", headers={"x-api-key": _WRONG}).status_code == 429
        assert client.options("/v1/findings", headers=preflight).status_code != 429


def test_standalone_mcp_keeps_oauth_discovery_public_during_a_block(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "1")

    async def discovery(request):
        return JSONResponse({"issuer": "https://issuer.example"})

    async def mcp(request):
        return JSONResponse({}, status_code=401)

    app = Starlette(
        routes=[Route("/.well-known/oauth-protected-resource", discovery), Route("/mcp", mcp, methods=["GET", "POST", "OPTIONS"])]
    )
    app.add_middleware(AuthFailureMiddleware)
    with TestClient(app, client=("192.0.2.153", 1000)) as client:
        assert client.post("/mcp", headers={"authorization": "Bearer wrong"}).status_code == 429
        assert client.get("/.well-known/oauth-protected-resource").status_code == 200
        # A non-preflight OPTIONS can reach the verifier, so it is limited as well.
        assert client.options("/mcp", headers={"authorization": "Bearer wrong"}).status_code == 429


# A burst of callers is not an outage


@pytest.mark.asyncio
async def test_a_burst_of_distinct_sources_queues_rather_than_being_refused(monkeypatch):
    policy = AuthFailurePolicy()

    def slow(_source, _now):
        time.sleep(0.03)
        return 0

    monkeypatch.setattr(policy.store, "remaining", slow)
    responses = await asyncio.gather(*(policy.before(_request(f"198.51.100.{n + 1}")) for n in range(24)))
    assert [response.status_code for response in responses if response is not None] == []


@pytest.mark.asyncio
async def test_a_stalled_store_stays_bounded_and_abandons_queued_reads(monkeypatch):
    policy = AuthFailurePolicy()
    gate = threading.Event()
    calls = []

    def stalled(source, _now):
        calls.append(source)
        gate.wait(1.5)
        return 0

    monkeypatch.setattr(policy.store, "remaining", stalled)
    started = time.monotonic()
    responses = await asyncio.gather(*(policy.before(_request(f"198.51.{n // 256}.{n % 256}")) for n in range(200)))
    elapsed = time.monotonic() - started
    gate.set()
    assert all(response.status_code == 503 for response in responses)
    assert elapsed < 1.2  # Refused at the deadline, not after draining a queue.
    assert len(calls) <= 8  # Reads abandoned at the deadline never run.
    for _ in range(200):
        if policy._outstanding == 0:
            break
        await asyncio.sleep(0.02)
    assert policy._outstanding == 0
    assert policy._source_work == {}


# Audit write errors


def test_audit_append_error_leaves_no_write_lock(monkeypatch, tmp_path):
    path = str(tmp_path / "audit.db")
    store = audit_log.SQLiteAuditLog(path, hmac_key=b"rollback-test-key")

    def disk_full(*_args):
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(store, "_upsert_checkpoint", disk_full)
    with pytest.raises(sqlite3.OperationalError):
        store.append(audit_log.AuditEntry(action="test.first"))
    other = sqlite3.connect(path, timeout=0.2)
    other.execute("BEGIN IMMEDIATE")
    other.rollback()
    other.close()


# Login routes mark what they verified


def _sso_app():
    from agent_bom.api.routes import enterprise

    app = FastAPI()
    app.include_router(enterprise.router, prefix="/v1")
    app.add_middleware(GlobalRateLimitMiddleware, rpm=300_000)
    return app


def _patch_oidc_callback(monkeypatch, error):
    from agent_bom.api import oidc_browser
    from agent_bom.api.routes import enterprise_routes

    monkeypatch.setattr("agent_bom.api.routes.enterprise._consume_oidc_login_state", lambda _state: None, raising=False)
    monkeypatch.setattr(enterprise_routes.sessions, "_consume_oidc_login_state", lambda _state: None, raising=False)
    monkeypatch.setattr(oidc_browser.OIDCBrowserConfig, "from_env", classmethod(lambda cls: SimpleNamespace()))
    monkeypatch.setattr(oidc_browser, "open_pkce_cookie", lambda _sealed: ("verifier", "nonce", "/"))
    monkeypatch.setattr(oidc_browser, "managed_trial_invitation_digest_from_pkce_cookie", lambda _sealed: None)

    def exchange(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(oidc_browser, "exchange_code_for_tokens", exchange)


def _patch_snowflake_callback(monkeypatch, error):
    from agent_bom.api import snowflake_oauth
    from agent_bom.api.routes.enterprise_routes import sso

    monkeypatch.setattr(sso, "_consume_snowflake_login_state", lambda _state: None)
    monkeypatch.setattr(snowflake_oauth.SnowflakeOAuthConfig, "from_env", classmethod(lambda cls: SimpleNamespace(tenant_id="default")))
    monkeypatch.setattr("agent_bom.api.oidc_browser.open_pkce_cookie", lambda _sealed: ("verifier", "nonce", "/"))

    def exchange(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(snowflake_oauth, "exchange_code_for_tokens", exchange)


@pytest.mark.parametrize(
    ("patcher", "path"),
    [
        (_patch_oidc_callback, "/v1/auth/oidc/callback?code=c&state=s"),
        (_patch_snowflake_callback, "/v1/auth/snowflake/callback?code=c&state=s"),
    ],
    ids=["oidc", "snowflake"],
)
def test_browser_callbacks_count_rejected_codes_and_not_provider_outages(monkeypatch, patcher, path):
    from agent_bom.api.oidc import OIDCError, OIDCProviderUnavailableError
    from agent_bom.api.oidc_browser import OIDC_PKCE_COOKIE_NAME

    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "2")
    monkeypatch.setattr(audit_log, "_audit_log", audit_log.InMemoryAuditLog())
    monkeypatch.setattr("agent_bom.api.routes.enterprise_routes._session_helpers._check_auth_session_rate_limit", lambda _r: None)
    cookie = {"cookie": f"{OIDC_PKCE_COOKIE_NAME}=sealed"}

    patcher(monkeypatch, OIDCProviderUnavailableError("connection refused"))
    with TestClient(_sso_app(), client=("192.0.2.160", 1000)) as client:
        assert {client.get(path, headers=cookie).status_code for _ in range(6)} == {401}

    patcher(monkeypatch, OIDCError("invalid_grant"))
    with TestClient(_sso_app(), client=("192.0.2.161", 1000)) as client:
        assert client.get(path, headers=cookie).status_code == 401
        assert client.get(path, headers=cookie).status_code == 429


def test_oidc_callback_missing_code_or_cookie_never_counts(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "2")
    monkeypatch.setattr("agent_bom.api.routes.enterprise_routes._session_helpers._check_auth_session_rate_limit", lambda _r: None)
    with TestClient(_sso_app(), client=("192.0.2.162", 1000)) as client:
        assert {client.get("/v1/auth/oidc/callback").status_code for _ in range(6)} == {401}


def test_saml_rejected_assertion_counts(monkeypatch):
    from agent_bom.api import saml
    from agent_bom.api.routes.enterprise_routes import sso

    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "2")
    monkeypatch.setattr(audit_log, "_audit_log", audit_log.InMemoryAuditLog())
    monkeypatch.setattr(saml, "saml_runtime_available", lambda: True)
    monkeypatch.setattr(sso, "_consume_saml_relay_state", lambda _state: None)

    def reject(*_args, **_kwargs):
        raise saml.SAMLError("signature invalid")

    config = SimpleNamespace(verify_response=reject, session_ttl_seconds=60)
    monkeypatch.setattr(saml.SAMLConfig, "from_env", classmethod(lambda cls: config))
    body = {"saml_response": "assertion", "relay_state": "relay"}
    with TestClient(_sso_app(), client=("192.0.2.163", 1000)) as client:
        assert client.post("/v1/auth/saml/login", json=body).status_code == 401
        assert client.post("/v1/auth/saml/login", json=body).status_code == 429


@pytest.mark.parametrize("module_name", ["agent_bom.api.oidc_browser", "agent_bom.api.snowflake_oauth"])
def test_token_endpoint_outage_is_not_a_failed_credential(monkeypatch, module_name):
    import importlib

    module = importlib.import_module(module_name)

    def refuse(*_args, **_kwargs):
        raise URLError(ConnectionRefusedError("connection refused"))

    monkeypatch.setattr(module, "urlopen", refuse)
    monkeypatch.setattr(module, "validate_url", lambda _url: None)
    monkeypatch.setattr(module, "discover_oidc", lambda _issuer: {"token_endpoint": "https://issuer.example/token"}, raising=False)
    config = _token_config(module, monkeypatch)
    with pytest.raises(Exception) as outage:
        module.exchange_code_for_tokens(config, code="c", code_verifier="v")
    assert not outage.value.counts_as_failed_credential

    def unavailable(*_args, **_kwargs):
        raise HTTPError("https://issuer.example/token", 503, "unavailable", {}, None)

    monkeypatch.setattr(module, "urlopen", unavailable)
    with pytest.raises(Exception) as server_error:
        module.exchange_code_for_tokens(config, code="c", code_verifier="v")
    assert not server_error.value.counts_as_failed_credential

    def rejected(*_args, **_kwargs):
        raise HTTPError("https://issuer.example/token", 400, "invalid_grant", {}, None)

    monkeypatch.setattr(module, "urlopen", rejected)
    with pytest.raises(Exception) as bad_code:
        module.exchange_code_for_tokens(config, code="c", code_verifier="v")
    assert bad_code.value.counts_as_failed_credential


def _token_config(module, monkeypatch):
    value = "https://issuer.example/value"
    return SimpleNamespace(
        enabled=True, oidc=SimpleNamespace(issuer=value), redirect_uri=value, client_id="c", client_secret="s", token_endpoint=value
    )


# Evidence stays visible when the receipt budget is spent


@pytest.mark.asyncio
async def test_failures_always_move_the_metric(monkeypatch):
    monkeypatch.setattr(audit_log, "_audit_log", audit_log.InMemoryAuditLog())
    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "1000")
    policy = AuthFailurePolicy()
    before = sum(metrics._auth_failures.snapshot().values())
    for number in range(101):
        request = _request(f"198.51.100.{number % 200 + 1}")
        request.state.authentication_failed = True
        await policy.after(request, JSONResponse({}, status_code=401))
    assert sum(metrics._auth_failures.snapshot().values()) - before == 101


def test_a_receipt_over_budget_moves_the_drop_count(monkeypatch):
    written = []
    monkeypatch.setattr(audit_log, "log_action", lambda action, **details: written.append((action, details)))
    receipts = AuthFailureReceipts()
    before = metrics._auth_receipts_dropped.snapshot().get("over_budget", 0)
    for _ in range(4):
        receipts.submit("198.51.100.1", 1.0, lambda *_a: False, status_code=401)
    assert receipts.flush()
    assert metrics._auth_receipts_dropped.snapshot().get("over_budget", 0) - before == 4


def test_many_sources_cannot_spend_the_budget_for_a_targets_first_receipt(tmp_path):
    store = SQLiteAuthFailureStore(str(tmp_path / "limits.db"))
    for number in range(34):
        for _ in range(3):
            store.audit_allowed(f"{number + 1}.51.100.1", 100)
    assert store.audit_allowed("203.0.113.9", 100) is True
    # Repeat receipts still respect the deployment ceiling.
    assert store.audit_allowed("198.52.100.200", 100) is True
    assert store.audit_allowed("198.52.100.200", 100) is False


def test_first_receipts_still_have_a_ceiling(tmp_path):
    store = SQLiteAuthFailureStore(str(tmp_path / "limits.db"))
    allowed = sum(store.audit_allowed(f"{n % 200 + 1}.{n // 200}.0.1", 100) for n in range(1000))
    assert 100 < allowed <= 400


# Integrity under the wrong key


def test_wrong_configured_key_is_cannot_verify_and_real_tampering_stays_exact(monkeypatch, tmp_path):
    from agent_bom.api.routes.enterprise_routes.governance import audit_integrity

    path = str(tmp_path / "audit.db")
    first = audit_log.SQLiteAuditLog(path, hmac_key=b"first-configured-key")
    for number in range(5):
        first.append(audit_log.AuditEntry(action=f"test.{number}", details={"tenant_id": "default"}))
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="default"))

    other = audit_log.SQLiteAuditLog(path, hmac_key=b"other-configured-key")
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: other)
    result = audit_integrity(request, limit=1000, include_runtime=False)
    assert (result["tampered"], result["verified"], result["unverifiable"]) == (0, 0, 5)
    assert "signing key" in result["chains"][0]["error"]

    same = audit_log.SQLiteAuditLog(path, hmac_key=b"first-configured-key")
    same._conn.execute("UPDATE audit_log SET action = 'changed' WHERE action = 'test.2'")
    same._conn.commit()
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: same)
    result = audit_integrity(request, limit=1000, include_runtime=False)
    assert (result["verified"], result["tampered"]) == (4, 1)


def test_first_configured_key_over_ephemeral_rows_is_cannot_verify(monkeypatch, tmp_path):
    from agent_bom.api.routes.enterprise_routes.governance import audit_integrity

    monkeypatch.setattr(audit_log, "_HMAC_ENV_KEY", None)
    monkeypatch.setattr(audit_log, "_HMAC_KEY", b"ephemeral-test-key")
    path = str(tmp_path / "audit.db")
    first = audit_log.SQLiteAuditLog(path)
    for number in range(5):
        first.append(audit_log.AuditEntry(action=f"test.{number}", details={"tenant_id": "default"}))
    monkeypatch.setattr(audit_log, "_HMAC_ENV_KEY", "configured-now")
    monkeypatch.setattr(audit_log, "_HMAC_KEY", b"configured-now")
    reopened = audit_log.SQLiteAuditLog(path)
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: reopened)
    result = audit_integrity(SimpleNamespace(state=SimpleNamespace(tenant_id="default")), limit=1000, include_runtime=False)
    assert (result["tampered"], result["unverifiable"]) == (0, 5)


# Over-long forwarding and malformed attestations


def test_over_long_forwarded_chain_keeps_the_callers_failure_budget(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_TRUSTED_PROXY_HOPS", "1")
    monkeypatch.setenv("AGENT_BOM_TRUSTED_PROXY_CIDRS", "192.0.2.0/24")
    policy = AuthFailurePolicy()
    filler = ", ".join(f"10.0.0.{n}" for n in range(40))
    long_chain = _request("192.0.2.1", [(b"x-forwarded-for", f"{filler}, 203.0.113.5".encode())])
    assert policy.source(long_chain) == "203.0.113.5"


def test_other_consumers_still_refuse_an_over_long_chain(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_TRUSTED_PROXY_HOPS", "1")
    monkeypatch.setenv("AGENT_BOM_TRUSTED_PROXY_CIDRS", "192.0.2.0/24")
    filler = ",".join(f"10.0.0.{n}" for n in range(40))
    assert resolve_forwarded_client_ip(peer_host="192.0.2.1", forwarded_for=f"{filler},203.0.113.5") == "192.0.2.1"


def test_non_ascii_proxy_attestation_is_a_counted_refusal(monkeypatch):
    from agent_bom.api import auth
    from agent_bom.api.auth import KeyStore

    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "2")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", "p" * 40)
    monkeypatch.setattr(auth, "_key_store", KeyStore())
    monkeypatch.setattr(audit_log, "_audit_log", audit_log.InMemoryAuditLog())

    async def secured(request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/v1/findings", secured)])
    app.add_middleware(APIKeyMiddleware, api_key="", allow_unauthenticated=False)
    app.add_middleware(GlobalRateLimitMiddleware, rpm=300_000)
    headers = {"x-agent-bom-subject": "person", "x-agent-bom-role": "viewer", "x-agent-bom-proxy-secret": "pässwörd".encode("latin-1")}
    with TestClient(app, client=("192.0.2.170", 1000), raise_server_exceptions=False) as client:
        statuses = []
        for _ in range(2):
            statuses.append(client.get("/v1/findings", headers=headers).status_code)
    assert statuses == [401, 429]


# Anonymous role decisions and the event loop


@pytest.mark.asyncio
async def test_a_key_store_read_on_the_anonymous_path_leaves_the_loop_free(monkeypatch):
    from agent_bom.api import auth
    from agent_bom.api.middleware import APIKeyMiddleware as Middleware

    release = threading.Event()
    reads = []

    class RemoteStore:
        def has_keys(self):
            reads.append(1)
            release.wait(2)
            return True

    monkeypatch.setattr(auth, "_key_store", RemoteStore())
    middleware = Middleware(lambda *_a: None, api_key="")
    pending = asyncio.create_task(middleware._credentials_configured())
    await asyncio.sleep(0.05)  # Runs only if the read left the loop.
    assert not pending.done()
    release.set()
    assert await pending is True
    # Keys present is the restrictive answer, so it may be reused briefly.
    assert await middleware._credentials_configured() is True
    assert len(reads) == 1


@pytest.mark.asyncio
async def test_no_keys_is_never_reused_so_a_new_key_applies_at_once(monkeypatch):
    from agent_bom.api import auth
    from agent_bom.api.middleware import APIKeyMiddleware as Middleware

    state = {"keys": False}

    class RemoteStore:
        def has_keys(self):
            return state["keys"]

    monkeypatch.setattr(auth, "_key_store", RemoteStore())
    middleware = Middleware(lambda *_a: None, api_key="")
    assert await middleware._credentials_configured() is False
    state["keys"] = True
    assert await middleware._credentials_configured() is True


@pytest.mark.parametrize("backing", ["memory", "sqlite"])
@pytest.mark.asyncio
async def test_local_key_stores_answer_without_a_worker_and_see_changes_at_once(monkeypatch, tmp_path, backing):
    import anyio.to_thread

    from agent_bom.api import auth
    from agent_bom.api.auth import KeyStore, Role, create_api_key
    from agent_bom.api.middleware import APIKeyMiddleware as Middleware
    from agent_bom.api.sqlite_key_store import SQLiteKeyStore

    store = KeyStore() if backing == "memory" else SQLiteKeyStore(str(tmp_path / "keys.db"))
    monkeypatch.setattr(auth, "_key_store", store)

    async def forbidden(*_args, **_kwargs):
        raise AssertionError("local read offloaded")

    monkeypatch.setattr(anyio.to_thread, "run_sync", forbidden)
    middleware = Middleware(lambda *_a: None, api_key="")
    assert await middleware._credentials_configured() is False
    _raw, key = create_api_key("person", Role.VIEWER)
    store.add(key)
    assert await middleware._credentials_configured() is True
    if backing == "sqlite":  # The in-memory store keeps revoked keys, which stays restrictive.
        store.remove(key.key_id)
        assert await middleware._credentials_configured() is False


def test_api_key_resolution_needs_no_separate_presence_read(monkeypatch):
    from agent_bom.api import auth

    class Store:
        def has_keys(self):
            raise AssertionError("verify already answers this")

        def verify(self, _raw):
            return None

    monkeypatch.setattr(auth, "_key_store", Store())

    async def secured(request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/v1/findings", secured)])
    app.add_middleware(APIKeyMiddleware, api_key="", allow_unauthenticated=False)
    with TestClient(app) as client:
        assert client.get("/v1/findings", headers={"x-api-key": "wrong"}).status_code == 401
