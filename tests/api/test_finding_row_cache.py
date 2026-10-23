"""First findings pages reuse the rebuilt scan-finding rows while every input is unchanged.

A reachability- or triage-filtered page (and the grouped landing) rebuilt the
whole scan-finding fold on every request. The rows depend on the job and hub
evidence, the tenant's exceptions (owners and suppressions), runtime and
workload evidence, the read window and the clock (an exception takes effect at
``approved_at`` and lapses at ``expires_at``). The first-page cache keys on a
fingerprint of all of them and expires at the next instant the clock alone
would change a row, so a cached page is the page an uncached read returns.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from agent_bom.api import finding_row_inputs, finding_walk_cache, scan_finding_read
from tests._demo_estate_fixtures import VIEWER

_NO_STORES: dict = {"hub": None, "job_store": None}
_KEY = ("t1", 90, None, None, "open", "effective_reach", "[]")


@pytest.fixture(autouse=True)
def _fresh_cache():
    finding_walk_cache.clear()
    yield
    finding_walk_cache.clear()


@pytest.fixture
def revision(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(finding_walk_cache, "_revision", lambda tenant_id, hub, job_store: ("1", "0"))


def _loader(loads: list[int], tag: str = "row"):
    def load() -> list[dict]:
        loads.append(1)
        return [{"id": f"{tag}-{len(loads)}"}]

    return load


def test_a_first_page_reuses_rows_only_while_the_input_fingerprint_matches(revision) -> None:
    loads: list[int] = []
    inputs = {"value": (("fp-1",), None)}
    read = lambda: finding_walk_cache.walk_rows(  # noqa: E731
        _KEY, tenant_id="t1", **_NO_STORES, continuation=False, load=_loader(loads), inputs=lambda: inputs["value"]
    )
    first = read()
    assert read() is first
    inputs["value"] = (("fp-2",), None)
    assert read() == [{"id": "row-2"}]
    assert len(loads) == 2


def test_without_an_input_fingerprint_a_first_page_still_recomputes(revision) -> None:
    loads: list[int] = []
    for _ in range(2):
        finding_walk_cache.walk_rows(_KEY, tenant_id="t1", **_NO_STORES, continuation=False, load=_loader(loads))
    assert len(loads) == 2


def test_an_entry_expires_at_the_clock_horizon(revision, monkeypatch: pytest.MonkeyPatch) -> None:
    loads: list[int] = []
    horizon = time.time() + 30
    read = lambda: finding_walk_cache.walk_rows(  # noqa: E731
        _KEY, tenant_id="t1", **_NO_STORES, continuation=False, load=_loader(loads), inputs=lambda: (("fp",), horizon)
    )
    read()
    read()
    assert len(loads) == 1
    monkeypatch.setattr(finding_walk_cache, "_wall_clock", lambda: horizon)
    read()
    assert len(loads) == 2


def test_tenants_never_share_a_first_page_entry(revision) -> None:
    loads: list[int] = []
    rows = {
        tenant: finding_walk_cache.walk_rows(
            (tenant, *_KEY[1:]),
            tenant_id=tenant,
            **_NO_STORES,
            continuation=False,
            load=_loader(loads, tenant),
            inputs=lambda: (("fp",), None),
        )
        for tenant in ("a", "b")
    }
    assert rows == {"a": [{"id": "a-1"}], "b": [{"id": "b-2"}]}


def test_cached_rows_are_bounded_by_total_row_count(revision, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(finding_walk_cache, "MAX_CACHED_ROWS", 3)
    for index in range(3):
        finding_walk_cache.walk_rows(
            (*_KEY[:-1], str(index)),
            tenant_id="t1",
            **_NO_STORES,
            continuation=False,
            load=lambda: [{"id": "x"}, {"id": "y"}],
            inputs=lambda: (("fp",), None),
        )
    assert finding_walk_cache.cached_row_count() <= 3


# ── The fingerprint covers every non-job input of the rebuild ───────────────


def _exception(**fields: object) -> SimpleNamespace:
    base = {"tenant_id": "t1", "exception_id": "e1", "status": "pending", "approved_at": "", "expires_at": "", "reason": "{}"}
    return SimpleNamespace(**{**base, **fields})


def _fp(tenant: str = "t1", jobs: tuple[str, ...] = (), **sources: object):
    return finding_row_inputs.scan_row_inputs(tenant, sources=sources, window_job_ids=jobs)


def test_each_exception_write_changes_the_fingerprint() -> None:
    empty = _fp(exceptions=[])[0]
    created = _fp(exceptions=[_exception()])[0]
    approved = _fp(exceptions=[_exception(status="approved")])[0]
    assert len({empty, created, approved}) == 3


def test_runtime_and_workload_evidence_change_the_fingerprint() -> None:
    from agent_bom.cloud.runtime_workload_evidence import RuntimeWorkloadEvidenceIndex
    from agent_bom.finding_runtime_evidence import RuntimeEvidenceIndex

    empty = _fp(runtime_events=RuntimeEvidenceIndex(), workload_runtime=None)[0]
    blocked = _fp(runtime_events=RuntimeEvidenceIndex(blocked=[{"agent": "a", "tool": "t"}]), workload_runtime=None)[0]
    workload = RuntimeWorkloadEvidenceIndex("t1")
    workload._by_workload["k"] = []
    with_workload = _fp(runtime_events=RuntimeEvidenceIndex(), workload_runtime=workload)[0]
    assert len({empty, blocked, with_workload}) == 3


def test_a_job_crossing_the_read_window_changes_the_fingerprint() -> None:
    from agent_bom.api.finding_page_filters import _row_inputs

    class Jobs:
        def list_summary(self, tenant_id=None, **_):  # type: ignore[no-untyped-def]
            return [
                {"job_id": "old", "completed_at": "2026-01-01T00:00:00+00:00", "created_at": "2026-01-01T00:00:00+00:00"},
                {"job_id": "new", "completed_at": "2026-06-01T00:00:00+00:00", "created_at": "2026-06-01T00:00:00+00:00"},
            ]

    def fingerprint(since: str) -> tuple[str, ...]:
        return _row_inputs(SimpleNamespace(tenant_id="t-window", window_since=since), Jobs())[0]

    assert fingerprint("2025-12-01T00:00:00+00:00") == fingerprint("2025-12-15T00:00:00+00:00")
    assert fingerprint("2026-02-01T00:00:00+00:00") != fingerprint("2025-12-01T00:00:00+00:00")


def test_the_horizon_is_the_next_exception_approval_or_expiry() -> None:
    now = datetime.now(timezone.utc)
    soon, later = now + timedelta(minutes=5), now + timedelta(days=2)
    exceptions = [
        _exception(exception_id="e1", approved_at=(now - timedelta(days=1)).isoformat(), expires_at=later.isoformat()),
        _exception(exception_id="e2", approved_at=soon.isoformat(), expires_at=later.isoformat()),
    ]
    horizon = _fp(exceptions=exceptions)[1]
    assert horizon is not None and abs(horizon - soon.timestamp()) < 1
    assert _fp(exceptions=[_exception(approved_at=(now - timedelta(days=1)).isoformat())])[1] is None


def test_the_tenant_is_part_of_the_fingerprint() -> None:
    assert _fp(tenant="a")[0] != _fp(tenant="b")[0]


# ── On the demo estate: one fold, byte-identical pages ──────────────────────

_PAGES = [
    {"reachability": "reachable"},
    {"reachability": "unassessed", "group_occurrences": "true", "include_facets": "true"},
    {"group_occurrences": "true", "include_facets": "true", "approximate_total": "true"},
    {"framework": "soc2", "control": "CC6.1", "group_occurrences": "true"},
    {"triage": "untriaged"},
]


def _count_folds(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls: list[int] = []
    original = scan_finding_read.current_findings_with_history

    def counting(*args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(scan_finding_read, "current_findings_with_history", counting)
    return calls


def _page(client: TestClient, params: dict) -> dict:
    body = client.get("/v1/findings", headers=VIEWER, params={"limit": 25, **params}).json()
    for key in ("window", "count_metadata"):
        body.pop(key, None)
    return body


def test_repeated_first_pages_fold_once_and_match_uncached_reads(demo_estate_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    folds = _count_folds(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_FINDING_WALK_CACHE", "0")
    uncached = [_page(demo_estate_client, params) for params in _PAGES]
    assert len(folds) >= len(_PAGES)

    monkeypatch.setenv("AGENT_BOM_FINDING_WALK_CACHE", "1")
    finding_walk_cache.clear()
    first = [_page(demo_estate_client, params) for params in _PAGES]
    repeated = []
    for params in _PAGES:
        before = len(folds)
        repeated.append(_page(demo_estate_client, params))
        assert len(folds) == before, f"{params} rebuilt the scan rows"

    assert first == uncached
    assert repeated == uncached


def test_a_triage_write_between_cached_reads_is_served_like_an_uncached_read(
    demo_estate_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    params = {"triage": "under_investigation"}
    cached_before = _page(demo_estate_client, params)
    from agent_bom.api.models import FindingTriageRequest
    from agent_bom.api.routes.enterprise_routes.findings import record_finding_triage

    record_finding_triage(
        tenant_id="default",
        actor="test",
        req=FindingTriageRequest(vulnerability_id="CVE-2020-14343", package="*", assignee="owner@example.test"),
    )
    cached_after = _page(demo_estate_client, params)
    monkeypatch.setenv("AGENT_BOM_FINDING_WALK_CACHE", "0")
    uncached_after = _page(demo_estate_client, params)

    assert cached_after == uncached_after
    assert cached_after["findings"] != cached_before["findings"]
    # Viewers see the assignee redacted; the triage write reached the cached page.
    owners = {row.get("owner") for row in cached_after["findings"] if "CVE-2020-14343" in str(row.get("vulnerability_id"))}
    assert owners == {"o***@e***.test"}


@pytest.mark.parametrize("flag", ["AGENT_BOM_SCAN_SNAPSHOT_READS", "AGENT_BOM_SCAN_SNAPSHOT_FAST_READS"])
def test_history_ledger_reads_are_never_reused_across_requests(revision, monkeypatch: pytest.MonkeyPatch, flag: str) -> None:
    """A history backfill writes the ledger without bumping the job revision, so ledger-backed folds always recompute."""
    from agent_bom.api import scan_finding_read

    monkeypatch.setenv(flag, "1")
    assert scan_finding_read.scan_rows_inputs("t1", None, SimpleNamespace(list_summary=lambda **_: [])) is None
    loads: list[int] = []
    for _ in range(2):
        finding_walk_cache.reuse_rows(("k",), tenant_id="t1", job_store=None, inputs=lambda: None, load=_loader(loads))
    assert len(loads) == 2
