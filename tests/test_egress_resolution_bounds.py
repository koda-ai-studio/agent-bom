"""The egress rebinding check cannot stall a scan on a slow resolver."""

from __future__ import annotations

import socket
import threading
import time

import pytest

from agent_bom.core import egress_resolution


class _RefusedError(Exception):
    pass


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch):
    egress_resolution.clear_resolution_cache()
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("https_proxy", raising=False)
    monkeypatch.delenv("ALL_PROXY", raising=False)
    monkeypatch.delenv("all_proxy", raising=False)
    yield
    egress_resolution.clear_resolution_cache()


def test_a_hung_resolver_is_refused_within_the_timeout(monkeypatch):
    release = threading.Event()

    def hung(*_args, **_kwargs):
        release.wait(10)
        raise socket.gaierror("late")

    monkeypatch.setattr(egress_resolution.socket, "getaddrinfo", hung)
    monkeypatch.setattr(egress_resolution, "RESOLUTION_TIMEOUT_SECONDS", 0.2)

    started = time.monotonic()
    with pytest.raises(_RefusedError, match="timed out"):
        egress_resolution.resolve_egress_hostname("slow.example", _RefusedError)
    release.set()

    assert time.monotonic() - started < 2


def test_successful_resolution_is_reused_for_the_same_host(monkeypatch):
    calls: list[str] = []
    answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    def resolver(host, *_args, **_kwargs):
        calls.append(host)
        return answer

    monkeypatch.setattr(egress_resolution.socket, "getaddrinfo", resolver)

    first = egress_resolution.resolve_egress_hostname("pypi.example", _RefusedError)
    second = egress_resolution.resolve_egress_hostname("pypi.example", _RefusedError)

    assert first == second == answer
    assert calls == ["pypi.example"]


def test_cached_answer_expires(monkeypatch):
    calls: list[str] = []

    def resolver(host, *_args, **_kwargs):
        calls.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    clock = [1000.0]
    monkeypatch.setattr(egress_resolution.socket, "getaddrinfo", resolver)
    monkeypatch.setattr(egress_resolution, "_monotonic", lambda: clock[0])

    egress_resolution.resolve_egress_hostname("pypi.example", _RefusedError)
    clock[0] += egress_resolution.RESOLUTION_CACHE_TTL_SECONDS + 1
    egress_resolution.resolve_egress_hostname("pypi.example", _RefusedError)

    assert calls == ["pypi.example", "pypi.example"]


def test_failures_are_not_cached(monkeypatch):
    outcomes = [socket.gaierror("down"), [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]]

    def resolver(*_args, **_kwargs):
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(egress_resolution.socket, "getaddrinfo", resolver)

    with pytest.raises(_RefusedError, match="Cannot resolve"):
        egress_resolution.resolve_egress_hostname("flaky.example", _RefusedError)
    assert egress_resolution.resolve_egress_hostname("flaky.example", _RefusedError)
