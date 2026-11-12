"""SIGTERM turns readiness off at once, and uvicorn's in-flight wait is bounded."""

from __future__ import annotations

import signal

import pytest
from fastapi.testclient import TestClient

from agent_bom.core import graceful_shutdown


@pytest.fixture(autouse=True)
def _reset_drain_state(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(graceful_shutdown, "_termination_requested", False)
    previous = signal.getsignal(signal.SIGTERM)
    yield
    signal.signal(signal.SIGTERM, previous)


def test_sigterm_marks_draining_and_still_runs_the_server_handler() -> None:
    seen: list[int] = []
    signal.signal(signal.SIGTERM, lambda signum, _frame: seen.append(signum))
    graceful_shutdown.install_sigterm_drain()
    assert graceful_shutdown.termination_requested() is False

    signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)  # type: ignore[operator]

    assert graceful_shutdown.termination_requested() is True
    assert seen == [signal.SIGTERM]


def test_installing_twice_does_not_chain_the_handler_twice() -> None:
    seen: list[int] = []
    signal.signal(signal.SIGTERM, lambda signum, _frame: seen.append(signum))
    graceful_shutdown.install_sigterm_drain()
    graceful_shutdown.install_sigterm_drain()
    signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)  # type: ignore[operator]
    assert seen == [signal.SIGTERM]


def test_readiness_reports_draining_as_soon_as_sigterm_arrives(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api import readiness, server

    monkeypatch.setattr(readiness, "evaluate_control_plane_readiness", lambda: readiness.ReadinessStatus(ready=True))
    client = TestClient(server.app)
    assert client.get("/readyz").status_code == 200

    monkeypatch.setattr(graceful_shutdown, "_termination_requested", True)
    response = client.get("/readyz")

    assert response.status_code == 503
    assert response.json() == {"status": "draining"}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(None, 10), ("0", 0), ("20", 20), ("-3", 10), ("soon", 10)],
)
def test_graceful_shutdown_seconds_is_bounded(monkeypatch: pytest.MonkeyPatch, raw: str | None, expected: int) -> None:
    if raw is None:
        monkeypatch.delenv("AGENT_BOM_GRACEFUL_SHUTDOWN_SECONDS", raising=False)
    else:
        monkeypatch.setenv("AGENT_BOM_GRACEFUL_SHUTDOWN_SECONDS", raw)
    assert graceful_shutdown.graceful_shutdown_seconds() == expected


def test_api_server_bounds_the_in_flight_request_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cli import _server

    monkeypatch.setenv("AGENT_BOM_GRACEFUL_SHUTDOWN_SECONDS", "12")
    kwargs = _server.uvicorn_server_kwargs()
    assert kwargs["timeout_graceful_shutdown"] == 12
    assert kwargs["lifespan"] == "on"
