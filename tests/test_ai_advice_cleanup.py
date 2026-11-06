"""AI advice is derived data: no store failure may reach the authoritative job delete or the TTL sweep."""

from __future__ import annotations

import pytest

from agent_bom.api import ai_assessment_store


class _Broken:
    def __init__(self, error: Exception) -> None:
        self._error = error

    def delete_scan(self, _tenant: str, _scan: str) -> int:
        raise self._error

    def delete_older_than(self, _cutoff: str) -> int:
        raise self._error


class _DatabaseGoneError(Exception):
    """Stands in for driver errors outside the builtin hierarchy, such as a closed Postgres pool."""


@pytest.mark.parametrize("error", [_DatabaseGoneError("the pool is already closed"), OSError("disk"), RuntimeError("x")])
def test_store_failures_never_escape_the_cleanup(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    monkeypatch.setattr(ai_assessment_store, "_STORE", _Broken(error))
    ai_assessment_store.discard_scan_advice("tenant-a", "scan-a")
    ai_assessment_store.expire_advice("2026-01-01T00:00:00Z")


def test_postgres_store_follows_the_shared_pool_after_a_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    pools = [object(), object()]
    current = {"pool": pools[0]}
    monkeypatch.setattr(ai_assessment_store, "_get_pool", lambda: current["pool"])
    store = ai_assessment_store.PostgresAIAssessmentStore.__new__(ai_assessment_store.PostgresAIAssessmentStore)
    store._injected_pool = None
    assert store._pool is pools[0]
    current["pool"] = pools[1]
    assert store._pool is pools[1]
    store._injected_pool = pools[0]
    assert store._pool is pools[0]
