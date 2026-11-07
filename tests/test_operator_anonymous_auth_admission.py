"""Explicit anonymous access must not depend on authentication failure state."""

import pytest
from starlette.testclient import TestClient

from agent_bom.api import server
from agent_bom.api.auth_failure_store import SQLiteAuthFailureStore
from agent_bom.api.browser_session import SESSION_COOKIE_NAME
from agent_bom.api.read_models.posture import PostureResponse


@pytest.fixture(autouse=True)
def anonymous_viewer(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_NO_AUTH_ROLE", "viewer")
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "0")


@pytest.mark.parametrize("failure", [RuntimeError, TimeoutError])
def test_opted_in_anonymous_viewer_read_does_not_query_auth_state(monkeypatch, failure):
    calls = []

    def unavailable(*args):
        calls.append(1)
        raise failure("synthetic auth state unavailable")

    monkeypatch.setattr(SQLiteAuthFailureStore, "remaining", unavailable)
    server.configure_api(api_key=None, allow_unauthenticated=True)
    response = TestClient(server.app).get("/v1/posture")
    assert response.status_code == 200, response.text
    # Both an empty history and a completed zero-artifact scan are valid
    # public posture responses; inventory state is not this auth contract.
    PostureResponse.model_validate(response.json())
    assert calls == []


@pytest.mark.parametrize(
    "headers",
    [
        {"authorization": "Bearer invalid"},
        {"authorization": "Basic invalid"},
        {"x-api-key": "invalid"},
        {"x-api-key": " "},
        {"cookie": f"{SESSION_COOKIE_NAME}=invalid"},
        {"x-agent-bom-role": "viewer"},
        {"x-agent-bom-tenant-id": "other-tenant"},
        {"x-agent-bom-subject": "synthetic-user"},
        {"x-agent-bom-proxy-secret": "invalid"},
        {"x-forwarded-email": "synthetic@example.invalid"},
        {"x-auth-request-email": "synthetic@example.invalid"},
    ],
)
def test_anonymous_mode_never_bypasses_auth_state_for_presented_credentials(monkeypatch, headers):
    def unavailable(*args):
        raise RuntimeError("synthetic auth state unavailable")

    monkeypatch.setattr(SQLiteAuthFailureStore, "remaining", unavailable)
    server.configure_api(api_key=None, allow_unauthenticated=True)
    response = TestClient(server.app).get("/v1/posture", headers=headers)
    assert response.status_code == 503, response.text


@pytest.mark.parametrize(
    ("method", "path"),
    [("GET", "/v1/auth/keys"), ("GET", "/v1/auth/oidc/callback"), ("GET", "/scim/v2/Users"), ("GET", "/v1/unclassified-read")],
)
def test_anonymous_admission_does_not_exempt_auth_or_unknown_routes(monkeypatch, method, path):
    def unavailable(*args):
        raise RuntimeError("synthetic auth state unavailable")

    monkeypatch.setattr(SQLiteAuthFailureStore, "remaining", unavailable)
    server.configure_api(api_key=None, allow_unauthenticated=True)
    response = TestClient(server.app).request(method, path)
    assert response.status_code == 503, response.text


@pytest.mark.parametrize(("role", "api_key", "expected"), [("viewer", None, 403), ("admin", None, 202), ("admin", "synthetic-key", 403)])
def test_anonymous_mutations_keep_configured_role_and_credential_clamp(monkeypatch, tmp_path, role, api_key, expected):
    from agent_bom.db import adoption_events

    calls = []

    def unavailable(*args):
        calls.append(1)
        raise RuntimeError("synthetic auth state unavailable")

    monkeypatch.setenv("AGENT_BOM_NO_AUTH_ROLE", role)
    monkeypatch.setattr(SQLiteAuthFailureStore, "remaining", unavailable)
    store = adoption_events.AdoptionEventStore(tmp_path / "events.db", enabled=True)
    monkeypatch.setattr(adoption_events, "_store", store)
    server.configure_api(api_key=api_key, allow_unauthenticated=True)
    response = TestClient(server.app).post(
        "/v1/observability/adoption/events",
        json={"event": "artifact_created", "channel": "control_plane", "artifact_type": "sarif"},
    )
    assert response.status_code == expected, response.text
    assert calls == []
    assert store.summary()["counts"].get("artifact_created", 0) == (1 if expected == 202 else 0)


def test_anonymous_reads_still_require_operator_opt_in(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)

    def unavailable(*args):
        raise RuntimeError("synthetic auth state unavailable")

    monkeypatch.setattr(SQLiteAuthFailureStore, "remaining", unavailable)
    server.configure_api(api_key="synthetic-configured-key", allow_unauthenticated=False)
    response = TestClient(server.app).get("/v1/posture")
    assert response.status_code == 503, response.text


def test_configured_scim_path_never_uses_anonymous_admission(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_SCIM_BASE_PATH", "/v1/posture")

    def unavailable(*args):
        raise RuntimeError("synthetic auth state unavailable")

    monkeypatch.setattr(SQLiteAuthFailureStore, "remaining", unavailable)
    server.configure_api(api_key=None, allow_unauthenticated=True)
    response = TestClient(server.app).get("/v1/posture")
    assert response.status_code == 503, response.text


def test_anonymous_reads_retain_global_limits_and_admin_role_denial(monkeypatch):
    monkeypatch.setattr(server, "global_ip_rate_limit_rpm", lambda: 3)
    server.configure_api(api_key=None, allow_unauthenticated=True)
    client = TestClient(server.app)
    assert client.get("/v1/auth/keys").status_code == 403
    assert client.get("/v1/posture").status_code == 200
    assert client.get("/v1/posture").status_code == 200
    limited = client.get("/v1/posture")
    assert limited.status_code == 429
    assert limited.headers["x-ratelimit-scope"] == "global-ip"


def test_source_backoff_still_blocks_presented_keys_in_anonymous_mode(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "1")
    server.configure_api(api_key="synthetic-valid-key", allow_unauthenticated=True)
    client = TestClient(server.app)
    assert client.get("/v1/posture", headers={"x-api-key": "wrong"}).status_code == 429
    assert client.get("/v1/posture").status_code == 200
    blocked = client.get("/v1/posture", headers={"x-api-key": "synthetic-valid-key"})
    assert blocked.status_code == 429
    assert blocked.headers["x-ratelimit-scope"] == "auth-source"
