"""Walking ``GET /v1/findings`` by cursor folds the scan findings once per walk.

Profiled on the demo estate (2,725 findings, 6 pages at ``limit=500``): the
walk took 12.5 s, 70% of it rebuilding the full scan-finding fold
(``current_findings_with_history``) on every page only to index into it at the
cursor's ``scan_index``. Continuation pages now reuse the rows their first page
built while the job and hub evidence revisions are unchanged. Cursor encoding
and page contents are unchanged.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agent_bom.api import finding_walk_cache, scan_finding_read
from tests.test_demo_estate_bootstrap import VIEWER, demo_estate_client  # noqa: F401

_NO_STORES: dict = {"hub": None, "job_store": None}


def _walk(client: TestClient) -> list[str]:
    ids: list[str] = []
    cursor = ""
    while True:
        params = {"limit": 500, **({"cursor": cursor} if cursor else {})}
        page = client.get("/v1/findings", headers=VIEWER, params=params).json()
        ids.extend(str(row["id"]) for row in page["findings"])
        cursor = page.get("next_cursor") or ""
        if not cursor:
            return ids


def _count_folds(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls: list[int] = []
    original = scan_finding_read.current_findings_with_history

    def counting(*args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(scan_finding_read, "current_findings_with_history", counting)
    return calls


def test_cursor_walk_folds_once_and_returns_the_same_pages(demo_estate_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    folds = _count_folds(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_FINDING_WALK_CACHE", "0")
    uncached = _walk(demo_estate_client)
    uncached_folds = len(folds)
    assert uncached_folds > 1, "the walk needs more than one page to prove anything"

    monkeypatch.setenv("AGENT_BOM_FINDING_WALK_CACHE", "1")
    finding_walk_cache.clear()
    folds.clear()
    cached = _walk(demo_estate_client)

    assert cached == uncached
    assert len(cached) == len(set(cached))
    assert len(folds) == 1, f"folded {len(folds)} times for one walk"


def test_continuation_recomputes_after_an_evidence_revision_change(monkeypatch: pytest.MonkeyPatch) -> None:
    finding_walk_cache.clear()
    revision = {"value": ("1", "0")}
    monkeypatch.setattr(finding_walk_cache, "_revision", lambda tenant_id, hub, job_store: revision["value"])
    loads: list[int] = []

    def load() -> list[dict]:
        loads.append(1)
        return [{"id": str(len(loads))}]

    key = ("t1", 90, None, None, "open", "effective_reach", "[]")
    first = finding_walk_cache.walk_rows(key, tenant_id="t1", **_NO_STORES, continuation=False, load=load)
    assert finding_walk_cache.walk_rows(key, tenant_id="t1", **_NO_STORES, continuation=True, load=load) is first
    revision["value"] = ("2", "0")
    assert finding_walk_cache.walk_rows(key, tenant_id="t1", **_NO_STORES, continuation=True, load=load) == [{"id": "2"}]
    assert len(loads) == 2


def test_first_pages_never_read_the_cache_and_tenants_never_share(monkeypatch: pytest.MonkeyPatch) -> None:
    finding_walk_cache.clear()
    monkeypatch.setattr(finding_walk_cache, "_revision", lambda tenant_id, hub, job_store: ("1", "0"))
    loads: list[str] = []

    def load_for(tenant: str):  # type: ignore[no-untyped-def]
        return lambda: loads.append(tenant) or [{"tenant": tenant}]

    key_a = ("a", 90, None, None, "open", "effective_reach", "[]")
    key_b = ("b", 90, None, None, "open", "effective_reach", "[]")
    finding_walk_cache.walk_rows(key_a, tenant_id="a", **_NO_STORES, continuation=False, load=load_for("a"))
    finding_walk_cache.walk_rows(key_a, tenant_id="a", **_NO_STORES, continuation=False, load=load_for("a"))
    assert finding_walk_cache.walk_rows(key_b, tenant_id="b", **_NO_STORES, continuation=True, load=load_for("b")) == [{"tenant": "b"}]
    assert loads == ["a", "a", "b"]


def test_store_without_a_revision_is_never_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    finding_walk_cache.clear()
    monkeypatch.setattr(finding_walk_cache, "_revision", lambda tenant_id, hub, job_store: None)
    loads: list[int] = []
    key = ("t1", 90, None, None, "open", "effective_reach", "[]")
    for continuation in (False, True):
        finding_walk_cache.walk_rows(key, tenant_id="t1", **_NO_STORES, continuation=continuation, load=lambda: loads.append(1) or [])
    assert len(loads) == 2
