"""Retained-job quota admission counts rows; it never loads every stored job body."""

from __future__ import annotations

import pytest

from agent_bom.api import tenant_quota


class _CountingStore:
    def __init__(self, count: int) -> None:
        self._count = count
        self.count_calls: list[str | None] = []

    def count_summary(self, tenant_id: str | None = None, *, query: str | None = None, status: object = None) -> int:
        assert query is None and status is None
        self.count_calls.append(tenant_id)
        return self._count

    def list_all(self, tenant_id: str | None = None, *, all_tenants: bool = False) -> list:
        raise AssertionError("quota admission must not deserialize every retained job")


def test_retained_jobs_quota_uses_a_count_query(monkeypatch) -> None:
    store = _CountingStore(count=3)
    monkeypatch.setattr(tenant_quota, "_get_store", lambda: store)
    monkeypatch.setattr(tenant_quota, "_quota_limit", lambda _tenant, _name: 5)

    tenant_quota.enforce_retained_jobs_quota("tenant-a")

    assert store.count_calls == ["tenant-a"]


def test_retained_jobs_quota_still_rejects_over_limit(monkeypatch) -> None:
    store = _CountingStore(count=5)
    monkeypatch.setattr(tenant_quota, "_get_store", lambda: store)
    monkeypatch.setattr(tenant_quota, "_quota_limit", lambda _tenant, _name: 5)

    with pytest.raises(Exception) as excinfo:
        tenant_quota.enforce_retained_jobs_quota("tenant-a")

    assert getattr(excinfo.value, "status_code", None) == 429
