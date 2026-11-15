"""Storage failures reach clients as the v1 error envelope, quickly.

A locked SQLite database used to surface as a plain-text 500 after a 30-second
busy wait, with no correlation id and no Retry-After. Any other unhandled
exception also escaped as plain text.
"""

from __future__ import annotations

import sqlite3
import time
import uuid

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient

from agent_bom.api import compliance_hub_store, stores
from agent_bom.api.server import app
from agent_bom.api.storage.sqlite_connection import api_sqlite_busy_timeout_ms
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

SECRET = "hunter2-not-a-real-secret"


@pytest.fixture()
def proxied(monkeypatch: pytest.MonkeyPatch):
    enable_trusted_proxy_env()
    yield
    disable_trusted_proxy_env()


@pytest.fixture()
def locked_sqlite(tmp_path, monkeypatch: pytest.MonkeyPatch, proxied):
    db_path = tmp_path / "jobs.db"
    sqlite3.connect(db_path).close()
    monkeypatch.setenv("AGENT_BOM_DB", str(db_path))
    monkeypatch.setenv("AGENT_BOM_API_SQLITE_BUSY_TIMEOUT_MS", "300")
    compliance_hub_store.reset_compliance_hub_store()
    holder = sqlite3.connect(db_path, isolation_level=None)
    holder.execute("BEGIN EXCLUSIVE")
    yield
    holder.execute("ROLLBACK")
    holder.close()
    compliance_hub_store.reset_compliance_hub_store()


def _assert_envelope(response, *, status: int, code: str) -> dict:
    assert response.status_code == status, response.text
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert body["error"]["code"] == code
    correlation_id = body["error"]["correlation_id"]
    assert correlation_id
    assert response.headers["X-Request-ID"] == correlation_id
    return body


def test_locked_sqlite_returns_a_fast_retryable_503_envelope(locked_sqlite) -> None:
    client = TestClient(app, raise_server_exceptions=False)
    started = time.perf_counter()
    response = client.get("/v1/findings?limit=5", headers=proxy_headers(role="viewer", tenant=f"t-{uuid.uuid4().hex[:8]}"))
    elapsed = time.perf_counter() - started

    body = _assert_envelope(response, status=503, code="SERVICE_UNAVAILABLE")
    assert int(response.headers["Retry-After"]) >= 1
    assert "locked" not in response.text.lower()
    assert "jobs.db" not in response.text
    assert body["error"]["message"]
    assert elapsed < 10, f"locked database answered after {elapsed:.1f}s"


def test_unhandled_exception_returns_an_enveloped_sanitized_500(monkeypatch: pytest.MonkeyPatch, proxied) -> None:
    def explode():
        raise RuntimeError(f"boom at /srv/agent-bom/state.db password={SECRET}")

    monkeypatch.setattr(compliance_hub_store, "get_compliance_hub_store", explode)
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/v1/findings?limit=5", headers=proxy_headers(role="viewer", tenant="t-500"))

    body = _assert_envelope(response, status=500, code="INTERNAL_ERROR")
    assert SECRET not in response.text
    assert "/srv/agent-bom" not in response.text
    assert "boom" not in response.text
    assert body["error"]["message"]


def test_non_lock_sqlite_error_is_a_500_not_a_503(monkeypatch: pytest.MonkeyPatch, proxied) -> None:
    def broken():
        raise sqlite3.OperationalError("no such table: compliance_hub_findings")

    monkeypatch.setattr(compliance_hub_store, "get_compliance_hub_store", broken)
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/v1/findings?limit=5", headers=proxy_headers(role="viewer", tenant="t-schema"))

    _assert_envelope(response, status=500, code="INTERNAL_ERROR")
    assert "compliance_hub_findings" not in response.text
    assert "Retry-After" not in response.headers


def test_locked_sqlite_on_push_returns_a_fast_503(locked_sqlite, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(stores, "_idempotency_store", None)
    client = TestClient(app, raise_server_exceptions=False)
    started = time.perf_counter()
    response = client.post(
        "/v1/results/push",
        json={"source_id": "locked-push", "findings": []},
        headers={**proxy_headers(role="admin", tenant="t-push"), "Idempotency-Key": "locked-push-1"},
    )
    elapsed = time.perf_counter() - started

    _assert_envelope(response, status=503, code="SERVICE_UNAVAILABLE")
    assert int(response.headers["Retry-After"]) >= 1
    assert elapsed < 10, f"locked push answered after {elapsed:.1f}s"


def test_busy_timeout_is_bounded_and_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_API_SQLITE_BUSY_TIMEOUT_MS", raising=False)
    assert api_sqlite_busy_timeout_ms() == 5_000
    monkeypatch.setenv("AGENT_BOM_API_SQLITE_BUSY_TIMEOUT_MS", "750")
    assert api_sqlite_busy_timeout_ms() == 750
    monkeypatch.setenv("AGENT_BOM_API_SQLITE_BUSY_TIMEOUT_MS", "999999999")
    assert api_sqlite_busy_timeout_ms() == 120_000


def test_postgres_connection_failure_is_a_503(monkeypatch: pytest.MonkeyPatch, proxied) -> None:
    # Same module and class name as psycopg's, so this runs without the postgres extra.
    pg_operational_error = type("OperationalError", (Exception,), {"__module__": "psycopg"})

    def unreachable():
        raise pg_operational_error(f"connection to server at 10.0.0.5 failed: password={SECRET}")

    monkeypatch.setattr(compliance_hub_store, "get_compliance_hub_store", unreachable)
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/v1/findings?limit=5", headers=proxy_headers(role="viewer", tenant="t-pg"))

    _assert_envelope(response, status=503, code="SERVICE_UNAVAILABLE")
    assert response.headers["Retry-After"] == "5"
    assert SECRET not in response.text
    assert "10.0.0.5" not in response.text


def _locked(*_args, **_kwargs):
    raise sqlite3.OperationalError(f"database is locked at /srv/agent-bom/jobs.db password={SECRET}")


def _push(client: TestClient, *, key: str | None, prefer: str | None = None):
    headers = proxy_headers(role="admin", tenant=f"t-{uuid.uuid4().hex[:8]}")
    if key:
        headers["Idempotency-Key"] = key
    if prefer:
        headers["Prefer"] = prefer
    return client.post("/v1/results/push", json={"source_id": f"src-{uuid.uuid4().hex[:6]}", "findings": []}, headers=headers)


def _logged(caplog: pytest.LogCaptureFixture) -> str:
    return "\n".join(record.getMessage() for record in caplog.records)


def _assert_storage_logged(caplog: pytest.LogCaptureFixture) -> None:
    text = _logged(caplog)
    assert "OperationalError" in text, text
    assert "database is locked" in text, text
    assert SECRET not in text
    assert "/srv/agent-bom" not in text
    assert "An internal error occurred" not in text


@pytest.mark.parametrize("key", [None, "commit-locked-1"])
def test_push_commit_hitting_a_locked_store_is_a_retryable_envelope(
    key: str | None, proxied, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from agent_bom.api.routes import observability

    monkeypatch.setattr(stores, "_idempotency_store", None)
    monkeypatch.setattr(observability, "_persist_graph_snapshot", _locked)
    client = TestClient(app, raise_server_exceptions=False)
    with caplog.at_level("WARNING", logger="agent_bom"):
        response = _push(client, key=key)

    _assert_envelope(response, status=503, code="SERVICE_UNAVAILABLE")
    assert response.headers["Retry-After"] == "5"
    assert SECRET not in response.text
    _assert_storage_logged(caplog)


def test_async_push_admission_hitting_a_locked_store_is_a_retryable_envelope(
    proxied, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from agent_bom.api.routes import observability

    monkeypatch.setattr(stores, "_idempotency_store", None)
    monkeypatch.setattr(observability, "admitted_push_result", _locked)
    client = TestClient(app, raise_server_exceptions=False)
    with caplog.at_level("WARNING", logger="agent_bom"):
        response = _push(client, key="async-locked-1", prefer="respond-async")

    _assert_envelope(response, status=503, code="SERVICE_UNAVAILABLE")
    assert response.headers["Retry-After"] == "5"
    _assert_storage_logged(caplog)


def test_push_commit_failure_that_is_not_storage_logs_its_class_and_sanitized_cause(
    proxied, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from agent_bom.api.routes import observability

    def broken(*_args, **_kwargs):
        raise ValueError(f"graph shape rejected at /srv/agent-bom/graph.db password={SECRET}")

    monkeypatch.setattr(stores, "_idempotency_store", None)
    monkeypatch.setattr(observability, "_persist_graph_snapshot", broken)
    client = TestClient(app, raise_server_exceptions=False)
    with caplog.at_level("WARNING", logger="agent_bom"):
        response = _push(client, key=None)

    _assert_envelope(response, status=503, code="SERVICE_UNAVAILABLE")
    assert SECRET not in response.text
    text = _logged(caplog)
    assert "ValueError" in text and "graph shape rejected" in text, text
    assert SECRET not in text and "/srv/agent-bom" not in text


def test_a_route_503_raised_from_a_storage_outage_carries_retry_after() -> None:
    from fastapi import FastAPI, HTTPException

    from agent_bom.api.error_envelope import install_error_envelope

    probe = FastAPI()
    install_error_envelope(probe)

    @probe.get("/locked")
    def locked() -> None:
        try:
            _locked()
        except sqlite3.OperationalError as exc:
            raise HTTPException(status_code=503, detail="Activity storage unavailable") from exc

    @probe.get("/not-configured")
    def not_configured() -> None:
        raise HTTPException(status_code=503, detail="Feature is not configured")

    client = TestClient(probe, raise_server_exceptions=False)
    response = client.get("/locked")
    _assert_envelope(response, status=503, code="SERVICE_UNAVAILABLE")
    assert response.headers["Retry-After"] == "5"
    assert response.json()["error"]["message"] == "Activity storage unavailable"
    assert "Retry-After" not in client.get("/not-configured").headers


def test_api_failure_logs_name_the_failure_class() -> None:
    """A log line reading only "An internal error occurred" cannot be triaged."""
    from pathlib import Path

    root = Path(stores.__file__).parent  # the agent_bom.api package directory
    offenders = [
        f"{path.relative_to(root)}:{number}"
        for path in sorted(root.rglob("*.py"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if "logger." in line and "generic=True" in line
    ]
    assert offenders == []
