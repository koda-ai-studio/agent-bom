"""Browser credentials obey live key lifecycle and reject malformed CSRF."""

import hashlib
import hmac
import json

import pytest
from fastapi import FastAPI, Request
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agent_bom.api.browser_session import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, SESSION_COOKIE_NAME, create_browser_session_token
from agent_bom.api.middleware import APIKeyMiddleware


def _issue():
    from agent_bom.api.secret_source import resolve_secret

    return create_browser_session_token(
        subject="static-key",
        role="admin",
        tenant_id="default",
        auth_method="browser_session_static_api_key",
        max_age_seconds=300,
        static_api_key=resolve_secret("AGENT_BOM_API_KEY"),
    )


def _app():
    async def protected(request):
        return JSONResponse({"tenant": request.state.tenant_id})

    app = Starlette(routes=[Route("/v1/scan", protected, methods=["GET", "POST"])])
    app.add_middleware(APIKeyMiddleware, api_key="")
    return app


@pytest.mark.parametrize("source", ["env", "file"])
@pytest.mark.parametrize("change", ["rotate", "remove"])
def test_static_key_change_invalidates_existing_browser_cookie(monkeypatch, tmp_path, source, change):
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "synthetic-persistent-signing-key")
    old_key = "synthetic-" + "login-one"
    key_file = tmp_path / "login-key"
    if source == "file":
        key_file.write_text(old_key)
        monkeypatch.setenv("AGENT_BOM_API_KEY_FILE", str(key_file))
    else:
        monkeypatch.setenv("AGENT_BOM_API_KEY", old_key)
    token, _ = _issue()
    with TestClient(_app()) as client:
        client.cookies.set(SESSION_COOKIE_NAME, token)
        assert client.get("/v1/scan").status_code == 200
        if source == "file":
            if change == "remove":
                key_file.unlink()
            else:
                key_file.write_text("synthetic-" + "login-two")
        elif change == "remove":
            monkeypatch.delenv("AGENT_BOM_API_KEY")
        else:
            monkeypatch.setenv("AGENT_BOM_API_KEY", "synthetic-" + "login-two")
        assert client.get("/v1/scan").status_code == 401
        if change == "rotate":
            client.cookies.set(SESSION_COOKIE_NAME, _issue()[0])
            assert client.get("/v1/scan").status_code == 200


def test_non_ascii_csrf_is_rejected_without_server_error(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_API_KEY", "synthetic-" + "login")
    token, csrf = _issue()
    with TestClient(_app(), raise_server_exceptions=False) as client:
        client.cookies.set(SESSION_COOKIE_NAME, token)
        client.cookies.set(CSRF_COOKIE_NAME, csrf)
        response = client.post("/v1/scan", headers={CSRF_HEADER_NAME: b"\xff", "origin": "http://testserver"})
        assert response.status_code == 403
        assert response.json()["detail"] == "Forbidden — missing or invalid CSRF token"


def _exchange_app(static_key=""):
    from agent_bom.api.middleware import install_error_envelope
    from agent_bom.api.routes.enterprise_routes.keys import router

    app = FastAPI()
    install_error_envelope(app)
    app.include_router(router, prefix="/v1")

    @app.get("/v1/scan")
    async def protected(request: Request):
        return {"tenant": request.state.tenant_id}

    app.add_middleware(APIKeyMiddleware, api_key=static_key)
    return app


@pytest.mark.parametrize("surface", ["exchange", "surrogate", "bearer"])
def test_non_ascii_api_credentials_are_unauthorized_not_server_errors(monkeypatch, surface):
    raw = "synthetic-" + "login"
    monkeypatch.setenv("AGENT_BOM_API_KEY", raw)
    with TestClient(_exchange_app(raw)) as client:
        if surface in {"exchange", "surrogate"}:
            # Send escaped JSON explicitly: HTTP clients correctly refuse to
            # encode a lone surrogate when constructing a normal JSON body.
            body = '{"api_key":"wrong-\\ud800"}' if surface == "surrogate" else '{"api_key":"wrong-\\u00ff"}'
            response = client.post("/v1/auth/session", content=body, headers={"content-type": "application/json"})
        else:
            response = client.get("/v1/scan", headers={"authorization": b"Bearer wrong-\xff"})
        assert response.status_code == (422 if surface == "surrogate" else 401)
        assert "wrong-" not in response.text


def test_real_exchange_binds_the_authenticated_key_during_rotation(monkeypatch):
    from agent_bom.api.routes.enterprise_routes import keys

    original = keys._set_browser_session_cookie
    raw = "synthetic-" + "login-one"
    monkeypatch.setenv("AGENT_BOM_API_KEY", raw)

    def rotate_before_issuance(*args, **kwargs):
        monkeypatch.setenv("AGENT_BOM_API_KEY", "synthetic-" + "login-two")
        return original(*args, **kwargs)

    with TestClient(_exchange_app()) as client:
        assert client.post("/v1/auth/session", json={"api_key": raw}).status_code == 204
        assert client.get("/v1/scan").json() == {"tenant": "default"}
        client.cookies.clear()
        monkeypatch.setattr(keys, "_set_browser_session_cookie", rotate_before_issuance)
        assert client.post("/v1/auth/session", json={"api_key": raw}).status_code == 204
        assert client.get("/v1/scan").status_code == 401


@pytest.mark.asyncio
async def test_static_cookie_stream_rechecks_key_rotation(monkeypatch):
    from agent_bom.api import stream_authorization

    monkeypatch.setenv("AGENT_BOM_API_KEY", "synthetic-" + "login-one")
    monkeypatch.setattr(stream_authorization, "STREAM_RECHECK_SECONDS", 0.0)
    leases = []

    async def protected(request):
        leases.append(request.state.stream_authorization)
        return JSONResponse({"tenant": request.state.tenant_id})

    app = Starlette(routes=[Route("/v1/scan/fixture/stream", protected)])
    app.add_middleware(APIKeyMiddleware, api_key="")
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, _issue()[0])
        assert client.get("/v1/scan/fixture/stream").status_code == 200
    assert await leases[0].allowed()
    monkeypatch.setenv("AGENT_BOM_API_KEY", "synthetic-" + "login-two")
    assert not await leases[0].allowed()


def test_static_cookie_is_rejected_when_cluster_policy_changes(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_API_KEY", "synthetic-" + "login")
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "synthetic-signing-key")
    with TestClient(_app()) as client:
        client.cookies.set(SESSION_COOKIE_NAME, _issue()[0])
        assert client.get("/v1/scan").status_code == 200
        monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", "2")
        assert client.get("/v1/scan").status_code == 401


def test_legacy_static_cookie_requires_fresh_exchange(monkeypatch):
    from agent_bom.api import browser_session as sessions

    monkeypatch.setenv("AGENT_BOM_API_KEY", "synthetic-" + "login")
    token, _ = _issue()
    payload = sessions.verify_browser_session_token(token)
    payload.pop("static_key_binding")
    encoded = sessions._b64encode(json.dumps(payload).encode())
    signature = hmac.new(sessions._signing_key(), encoded.encode(), hashlib.sha256).digest()
    legacy = f"{encoded}.{sessions._b64encode(signature)}"
    with TestClient(_app()) as client:
        client.cookies.set(SESSION_COOKIE_NAME, legacy)
        assert client.get("/v1/scan").status_code == 401
        client.cookies.set(SESSION_COOKIE_NAME, token)
        assert client.get("/v1/scan").status_code == 200


def test_static_key_binding_is_nonce_specific_and_contains_no_raw_key(monkeypatch):
    from agent_bom.api.browser_session import verify_browser_session_token

    raw = "synthetic-" + "login"
    monkeypatch.setenv("AGENT_BOM_API_KEY", raw)
    payloads = [verify_browser_session_token(_issue()[0]) for _ in range(2)]
    assert payloads[0]["static_key_binding"] != payloads[1]["static_key_binding"]
    assert all(raw not in json.dumps(payload) for payload in payloads)


def test_static_session_issuance_requires_authenticated_key():
    from agent_bom.api.browser_session import BrowserSessionError

    with pytest.raises(BrowserSessionError, match="authenticated backing key"):
        create_browser_session_token(
            subject="static-key", role="admin", tenant_id="default", auth_method="browser_session_static_api_key", max_age_seconds=300
        )


def test_logout_revokes_cookie_even_after_backing_key_changes(monkeypatch):
    raw = "synthetic-" + "login-one"
    monkeypatch.setenv("AGENT_BOM_API_KEY", raw)
    with TestClient(_exchange_app()) as client:
        assert client.post("/v1/auth/session", json={"api_key": raw}).status_code == 204
        token = client.cookies.get(SESSION_COOKIE_NAME)
        csrf = client.cookies.get(CSRF_COOKIE_NAME)
        monkeypatch.setenv("AGENT_BOM_API_KEY", "synthetic-" + "login-two")
        assert client.get("/v1/scan").status_code == 401
        assert client.delete("/v1/auth/session", headers={"origin": "http://testserver", CSRF_HEADER_NAME: csrf}).status_code == 204
        monkeypatch.setenv("AGENT_BOM_API_KEY", raw)
        client.cookies.clear()
        client.cookies.set(SESSION_COOKIE_NAME, token)
        assert client.get("/v1/scan").status_code == 401


@pytest.mark.parametrize("rotate", [False, True])
@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_operator_slot_session_tracks_credential_changes(monkeypatch, tmp_path, rotate, backend):
    from agent_bom.api import auth
    from agent_bom.api.operator_keys import seed_operator_keys
    from agent_bom.api.sqlite_key_store import SQLiteKeyStore

    db = str(tmp_path / "keys.db")
    store = auth.KeyStore() if backend == "memory" else SQLiteKeyStore(db)
    monkeypatch.setattr(auth, "_key_store", store)
    raw = "synthetic-" + "operator-one"
    seed_operator_keys("env", [(raw, "configured", auth.Role.ADMIN)])
    with TestClient(_exchange_app()) as client:
        assert client.post("/v1/auth/session", json={"api_key": raw}).status_code == 204
        assert client.get("/v1/scan").status_code == 200
        if backend == "sqlite":
            monkeypatch.setattr(auth, "_key_store", SQLiteKeyStore(db))
        replacement = "synthetic-" + "operator-two" if rotate else raw
        seed_operator_keys("env", [(replacement, "configured", auth.Role.ADMIN)])
        assert client.get("/v1/scan").status_code == (401 if rotate else 200)
