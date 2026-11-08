"""Authentication and rate-limit state share one bounded pool per process.

The bootstrap application role permits 20 connections. A pool per kind of
admission state pushed two API replicas, two gateways and the verification job
past that limit, so the Helm install failed.
"""

from __future__ import annotations

from agent_bom.api import rate_limit_store


class _Pool:
    def __init__(self, max_size: int) -> None:
        self.max_size = max_size
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_auth_and_rate_limit_state_share_one_bounded_pool(monkeypatch):
    app_pool = object()
    created: list[_Pool] = []

    def new_pool(*, min_size: int, max_size: int, autocommit: bool = False) -> _Pool:
        assert autocommit
        pool = _Pool(max_size)
        created.append(pool)
        return pool

    monkeypatch.setattr(rate_limit_store, "_get_pool", lambda: app_pool)
    monkeypatch.setattr(rate_limit_store, "_new_application_pool", new_pool)
    monkeypatch.setattr(rate_limit_store, "_guard_rls_capable_role", lambda pool: None)
    monkeypatch.setattr(rate_limit_store, "POSTGRES_POOL_MAX_SIZE", 20)
    monkeypatch.setattr(rate_limit_store, "_admission_pool", None)

    auth = rate_limit_store.admission_state_pool()
    rate_limit = rate_limit_store.admission_state_pool()

    assert auth is rate_limit
    assert len(created) == 1
    assert created[0].max_size <= 4


def test_admission_pool_follows_a_new_application_pool(monkeypatch):
    app_pools = [object()]
    created: list[_Pool] = []

    def new_pool(*, min_size: int, max_size: int, autocommit: bool = False) -> _Pool:
        pool = _Pool(max_size)
        created.append(pool)
        return pool

    monkeypatch.setattr(rate_limit_store, "_get_pool", lambda: app_pools[-1])
    monkeypatch.setattr(rate_limit_store, "_new_application_pool", new_pool)
    monkeypatch.setattr(rate_limit_store, "_guard_rls_capable_role", lambda pool: None)
    monkeypatch.setattr(rate_limit_store, "_admission_pool", None)

    first = rate_limit_store.admission_state_pool()
    app_pools.append(object())
    second = rate_limit_store.admission_state_pool()

    assert first is not second
    assert first.closed
    assert len(created) == 2
