"""AGENT_BOM_API_ROLE splits HTTP replicas from queue workers without silent idling."""

from __future__ import annotations

import pytest

from agent_bom.api import scan_queue


class _DispatchStore:
    def enqueue_for_dispatch(self, job): ...  # noqa: ANN001, ANN201
    def claim_next(self, worker_id, lease): ...  # noqa: ANN001, ANN201
    def renew_leases(self, claims, lease): ...  # noqa: ANN001, ANN201
    def complete_dispatch(self, job_id, **kwargs): ...  # noqa: ANN001, ANN003, ANN201
    def requeue_expired_leases(self): ...  # noqa: ANN201


@pytest.mark.parametrize("raw,expected", [(None, "all"), ("", "all"), ("API", "api"), (" worker ", "worker")])
def test_api_role_parses(monkeypatch: pytest.MonkeyPatch, raw: str | None, expected: str) -> None:
    if raw is None:
        monkeypatch.delenv("AGENT_BOM_API_ROLE", raising=False)
    else:
        monkeypatch.setenv("AGENT_BOM_API_ROLE", raw)
    assert scan_queue.api_role() == expected


def test_unknown_role_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_API_ROLE", "scheduler")
    with pytest.raises(ValueError):
        scan_queue.api_role()


def test_api_replicas_never_run_the_claim_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_API_ROLE", "api")
    monkeypatch.setattr(scan_queue, "distributed_scans_enabled", lambda: True)
    assert scan_queue.dispatch_worker_enabled(_DispatchStore()) is False


def test_worker_role_requires_distributed_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_API_ROLE", "worker")
    monkeypatch.setattr(scan_queue, "distributed_scans_enabled", lambda: False)
    with pytest.raises(RuntimeError):
        scan_queue.dispatch_worker_enabled(_DispatchStore())
    monkeypatch.setattr(scan_queue, "distributed_scans_enabled", lambda: True)
    assert scan_queue.dispatch_worker_enabled(_DispatchStore()) is True


def test_default_role_keeps_single_process_behaviour(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_API_ROLE", raising=False)
    monkeypatch.setattr(scan_queue, "distributed_scans_enabled", lambda: False)
    assert scan_queue.dispatch_worker_enabled(_DispatchStore()) is False
    monkeypatch.setattr(scan_queue, "distributed_scans_enabled", lambda: True)
    assert scan_queue.dispatch_worker_enabled(_DispatchStore()) is True
