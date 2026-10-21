"""Parity of scan/bulk paging across durable and in-memory current stores."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from agent_bom.api import finding_cursor, findings_count_cache
from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, SQLiteComplianceHubStore
from agent_bom.api.finding_page_filters import _filter_finding_rows, _findings_page
from agent_bom.api.finding_page_query import _FindingListQuery
from agent_bom.api.finding_scope_filters import _finding_sort_key


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    findings_count_cache.reset_findings_count_cache()
    result = InMemoryComplianceHubStore() if request.param == "memory" else SQLiteComplianceHubStore(str(tmp_path / "findings.db"))
    for tenant in ("tenant-a", "tenant-b"):
        rows = [
            {
                "id": f"bulk-{i}",
                "canonical_id": f"bulk-{i}",
                "origin": "bulk_ingest",
                "source": "test",
                "severity": "high" if i < 3 else "low",
                "cvss_score": float(9 - i),
                "effective_reach_score": float(90 - 10 * i),
                "provider": "aws" if i % 2 else "azure",
                "scan_id": "batch",
                "title": tenant,
            }
            for i in range(8)
        ]
        result.add(tenant, rows)
        result.upsert_current_batch(tenant, rows, observed_at="2026-10-01T00:00:00Z", batch_id="batch", source="test")
    yield result
    findings_count_cache.reset_findings_count_cache()


def query(**changes):
    values = dict(
        tenant_id="tenant-a",
        sort_key="effective_reach",
        severity=None,
        status_key="all",
        scan_id=None,
        limit=2,
        offset=0,
        cursor=None,
        merged_cursor=None,
        window_days=0,
        window_since=None,
        scope_filters={},
        approximate_total=False,
        cached_bulk_total=None,
        include_bulk_total=True,
    )
    return _FindingListQuery(**(values | changes))


@pytest.mark.parametrize("sort", ["effective_reach", "cvss", "severity"])
@pytest.mark.parametrize("filters", [{}, {"severity": "high"}, {"scope_filters": {"provider": "aws"}}])
@pytest.mark.parametrize("with_scan", [False, True])
def test_all_pages_preserve_source_rows_filters_and_tenant(store, sort, filters, with_scan):
    request = query(sort_key=sort, **filters)
    scan = (
        [
            {
                "id": "scan",
                "canonical_id": "scan",
                "severity": "high",
                "cvss_score": 9.5,
                "effective_reach_score": 95.0,
                "provider": "aws",
                "title": "tenant-a",
            }
        ]
        if with_scan
        else []
    )
    scan = _filter_finding_rows(scan, request)
    bulk = store.list_current_page("tenant-a", limit=100, sort=sort, status="all", origin="bulk_ingest")[0]
    expected = sorted(scan + _filter_finding_rows(bulk, request), key=lambda row: _finding_sort_key(row, sort))
    seen, cursors = [], set()
    for _ in range(20):
        metadata = {}
        page = _findings_page(request, scan, store, metadata)
        seen.extend(page.rows)
        if request.scope_filters:
            assert metadata["truncated"] is False
        if request.scope_filters and request.cursor:
            assert page.total is None and page.total_approximate
        else:
            assert page.total == len(expected) and not page.total_approximate
        if not page.next_cursor:
            break
        assert page.next_cursor not in cursors
        cursors.add(page.next_cursor)
        request = request._replace(
            cursor=page.next_cursor,
            include_bulk_total=False,
            merged_cursor=finding_cursor.decode_merged_scan_cursor(page.next_cursor, expected_sort=sort),
        )
    else:
        pytest.fail("cursor walk did not terminate")
    assert seen == expected
    assert {row["title"] for row in seen} == {"tenant-a"}
    assert len({row["id"] for row in seen}) == len(seen)


def test_current_reader_does_not_enumerate_ledger(store):
    store.list = Mock(side_effect=AssertionError("must page current rows, not enumerate the ledger"))
    page = _findings_page(query(limit=3, offset=2), [], store, {})
    assert [row["id"] for row in page.rows] == ["bulk-2", "bulk-3", "bulk-4"]
    assert page.total == 8


@pytest.mark.parametrize("with_scan", [False, True])
def test_empty_bounded_bulk_page_preserves_frontier_without_reading_past_budget(with_scan):
    from agent_bom.api.finding_merge import _merged_scan_bulk_page

    checkpoint = finding_cursor.encode_finding_cursor(sort="effective_reach", primary=99, last_seen="", canonical_id="unmatched")
    later = {"id": "later", "canonical_id": "later", "effective_reach_score": 95.0}
    scan = [{"id": "scan", "effective_reach_score": 90.0}] if with_scan else []
    metadata = {}
    calls = []

    def fetch(_tenant, **kwargs):
        calls.append(kwargs["cursor"])
        if kwargs["cursor"] is None:
            kwargs["scope_metadata"].update(truncated=True, scanned_rows=25, scan_budget=25, reason="scan_budget")
            return [], None, checkpoint
        return [later], None, None

    first = _merged_scan_bulk_page(
        scan,
        bulk_list=fetch,
        tenant_id="tenant-a",
        sort_key="effective_reach",
        severity=None,
        scan_id=None,
        offset=0,
        limit=3,
        scope={"provider": "aws"},
        scope_metadata=metadata,
    )
    assert first.rows == []
    assert first.has_more and first.next_bulk_cursor == checkpoint
    assert first.next_scan_index == 0
    assert calls == [None]
    assert metadata["truncated"]
    second = _merged_scan_bulk_page(
        scan,
        bulk_list=fetch,
        tenant_id="tenant-a",
        sort_key="effective_reach",
        severity=None,
        scan_id=None,
        offset=0,
        limit=3,
        scan_start=first.next_scan_index,
        bulk_cursor=first.next_bulk_cursor,
        scope={"provider": "aws"},
        scope_metadata={},
    )
    assert second.rows == [later, *scan]
    assert not second.has_more


def test_scan_resume_indexes_the_frontier_without_rewalking_the_prefix():
    from agent_bom.api.finding_merge import _merged_scan_bulk_page

    class IndexedRows(list):
        def __iter__(self):
            raise AssertionError("resuming a scan cursor must not iterate its prefix")

        def __getitem__(self, index):
            assert index >= 999, "already consumed scan rows must not be read again"
            return super().__getitem__(index)

    scan = IndexedRows([{"id": str(i), "effective_reach_score": 1.0} for i in range(1001)])
    page = _merged_scan_bulk_page(
        scan,
        bulk_list=lambda *args, **kwargs: ([], 0, None),
        tenant_id="tenant-a",
        sort_key="effective_reach",
        severity=None,
        scan_id=None,
        offset=0,
        limit=1,
        scan_start=999,
    )
    assert [row["id"] for row in page.rows] == ["999"]
    assert page.next_scan_index == 1000 and page.has_more
