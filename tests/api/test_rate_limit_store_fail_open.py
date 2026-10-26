"""A shared rate-limit store outage must never take down probes or the API."""

from __future__ import annotations

import threading
import time
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.testclient import TestClient

from agent_bom.api.error_envelope import with_middleware_error_envelope
from agent_bom.api.middleware import GlobalRateLimitMiddleware, RateLimitMiddleware, install_error_envelope
from agent_bom.api.rate_limit_store import FailOpenRateLimitStore, PostgresRateLimitStore


class _RaisingStore:
    def __init__(self) -> None:
        self.calls = 0

    def hit(self, key: str, now: float) -> tuple[int, int]:
        self.calls += 1
        raise ConnectionError("database is down")


class _HangingStore:
    def __init__(self) -> None:
        self.calls = 0
        self.release = threading.Event()
        self.returned = threading.Event()

    def hit(self, key: str, now: float) -> tuple[int, int]:
        self.calls += 1
        # Hangs until the test releases it, so a response can only come back
        # first through the store timeout.
        self.release.wait(30)
        self.returned.set()
        return 1, int(now) + 60


def _app(middleware, store, **kwargs) -> FastAPI:
    app = FastAPI()
    install_error_envelope(app)

    for path in ("/health", "/healthz", "/livez", "/readyz", "/ping"):
        app.add_api_route(path, lambda: {"status": "ok"})

    @app.get("/v1/jobs")
    def jobs():
        return {"jobs": []}

    with patch("agent_bom.api.middleware_limits._build_rate_limit_store", return_value=store):
        app.add_middleware(middleware, **kwargs)
        # One portal (event loop) for every request, as in a served process.
        client = TestClient(app).__enter__()
    app.state.client = client
    return app


@pytest.mark.parametrize(
    "middleware, kwargs",
    [
        (GlobalRateLimitMiddleware, {"rpm": 2}),
        (RateLimitMiddleware, {"read_rpm": 2}),
    ],
)
def test_store_error_fails_open_to_process_local_limits(middleware, kwargs):
    store = _RaisingStore()
    client = _app(middleware, store, **kwargs).state.client

    assert client.get("/v1/jobs").status_code == 200
    assert client.get("/v1/jobs").status_code == 200
    limited = client.get("/v1/jobs")
    assert limited.status_code == 429
    assert limited.json()["error"]["code"]
    # The first failure opens the breaker: later requests skip the dead store.
    assert store.calls == 1


@pytest.mark.parametrize(
    "middleware, kwargs",
    [
        (GlobalRateLimitMiddleware, {"rpm": 100}),
        (RateLimitMiddleware, {"read_rpm": 100}),
    ],
)
def test_hanging_store_is_bounded_by_a_short_timeout(middleware, kwargs):
    store = _HangingStore()
    client = _app(middleware, store, **kwargs).state.client

    try:
        assert client.get("/v1/jobs").status_code == 200
        assert client.get("/v1/jobs").status_code == 200
        assert not store.returned.is_set()
        assert store.calls == 1
    finally:
        store.release.set()


@pytest.mark.parametrize("path", ["/health", "/healthz", "/livez", "/readyz", "/ping"])
def test_probe_paths_bypass_the_global_limiter_store(path):
    store = _RaisingStore()
    client = _app(GlobalRateLimitMiddleware, store, rpm=1).state.client
    store.calls = 0

    for _ in range(5):
        assert client.get(path).status_code == 200
    assert store.calls == 0


def test_global_limiter_still_counts_api_routes():
    from agent_bom.api.rate_limit_store import InMemoryRateLimitStore

    client = _app(GlobalRateLimitMiddleware, InMemoryRateLimitStore(), rpm=1).state.client
    assert client.get("/v1/jobs").status_code == 200
    assert client.get("/v1/jobs").status_code == 429


def test_breaker_retries_the_shared_store_after_cooldown():
    store = _RaisingStore()
    limiter = FailOpenRateLimitStore(store, window_seconds=60, timeout_seconds=0.5, cooldown_seconds=0.05)
    import asyncio

    asyncio.run(limiter.hit_async("k", time.time()))
    asyncio.run(limiter.hit_async("k", time.time()))
    assert store.calls == 1
    time.sleep(0.06)
    asyncio.run(limiter.hit_async("k", time.time()))
    assert store.calls == 2


def test_degraded_logging_is_rate_limited(caplog):
    import asyncio

    store = _RaisingStore()
    limiter = FailOpenRateLimitStore(store, window_seconds=60, timeout_seconds=0.5, cooldown_seconds=0.0)
    with caplog.at_level("WARNING", logger="agent_bom.api.rate_limit_store"):
        for _ in range(5):
            asyncio.run(limiter.hit_async("k", time.time()))
    assert store.calls == 5
    warnings = [r for r in caplog.records if "process-local" in r.getMessage()]
    assert len(warnings) == 1
    assert "database is down" not in caplog.text


class _BackendDownMiddleware(BaseHTTPMiddleware):
    @with_middleware_error_envelope
    async def dispatch(self, request, call_next):
        import psycopg

        raise psycopg.OperationalError("connection to server at 10.0.0.5 failed")


def test_backend_unavailable_in_admission_returns_503_envelope():
    pytest.importorskip("psycopg")
    app = FastAPI()
    install_error_envelope(app)

    @app.get("/v1/jobs")
    def jobs():
        return {"jobs": []}

    app.add_middleware(_BackendDownMiddleware)
    response = TestClient(app, raise_server_exceptions=False).get("/v1/jobs", headers={"x-request-id": "db-down"})
    assert response.status_code == 503
    body = response.json()
    assert body["error"]["code"] == "SERVICE_UNAVAILABLE"
    assert body["error"]["correlation_id"] == "db-down"
    assert "10.0.0.5" not in response.text


class _UnrelatedFailureMiddleware(BaseHTTPMiddleware):
    @with_middleware_error_envelope
    async def dispatch(self, request, call_next):
        raise ValueError("bug")


def test_unrelated_admission_errors_are_not_masked_as_503():
    app = FastAPI()
    app.add_middleware(_UnrelatedFailureMiddleware)
    response = TestClient(app, raise_server_exceptions=False).get("/v1/jobs")
    assert response.status_code == 500


class _RecordingConn:
    def __init__(self, statements: list[str]) -> None:
        self._statements = statements

    def execute(self, sql, params=None):
        self._statements.append(" ".join(str(sql).split()))
        return self

    def fetchone(self):
        return (1, 0.0)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _RecordingPool:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def connection(self):
        return _RecordingConn(self.statements)


def test_postgres_hot_path_prune_is_bucket_scoped_and_global_prune_is_periodic():
    pool = _RecordingPool()
    store = object.__new__(PostgresRateLimitStore)
    store._window = 60
    store._pool = pool
    store._next_global_prune = 0.0

    now = time.time()
    store.hit("ip:a", now)
    store.hit("ip:b", now + 1)
    deletes = [sql for sql in pool.statements if sql.startswith("DELETE")]
    bucket_deletes = [sql for sql in deletes if "bucket_key = %s" in sql]
    global_deletes = [sql for sql in deletes if "bucket_key" not in sql]
    assert len(bucket_deletes) == 2
    assert len(global_deletes) == 1


def test_readiness_reports_not_ready_instead_of_hanging(monkeypatch):
    import asyncio
    import json
    import threading

    from agent_bom.api import readiness

    release = threading.Event()
    check_finished = threading.Event()

    def _stalled():
        # Stalls until the test releases it, so the response can only arrive first
        # through the readiness deadline.
        release.wait(30)
        check_finished.set()
        return readiness.ReadinessStatus(ready=True)

    monkeypatch.setattr(readiness, "evaluate_control_plane_readiness", _stalled)
    monkeypatch.setattr(readiness, "READINESS_TIMEOUT_SECONDS", 0.2)

    async def _probe():
        try:
            result = await readiness.control_plane_readiness_response(lambda: False)
            return result, check_finished.is_set()
        finally:
            release.set()

    response, waited_for_check = asyncio.run(_probe())
    assert waited_for_check is False
    assert response.status_code == 503
    assert json.loads(response.body) == {"status": "not_ready", "reason": "readiness_timeout"}


def test_readiness_reports_database_unavailable_when_postgres_errors(monkeypatch):
    from agent_bom.api import postgres_common, readiness

    class _DownPool:
        def connection(self):
            raise ConnectionError("down")

    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://example.invalid/agent_bom")
    monkeypatch.setattr(postgres_common, "_get_pool", lambda: _DownPool())
    assert readiness.evaluate_control_plane_readiness() == readiness.ReadinessStatus(ready=False, reason="database_unavailable")
