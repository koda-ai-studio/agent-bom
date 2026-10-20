"""Cursor pages of ``GET /v1/findings`` report the same exact total as page one.

Regression: resume pages (merged scan + bulk cursor, and plain bulk keyset
cursors) answered ``total: null`` / ``total_kind: unknown`` even though the
unscoped filter set is countable, so clients lost the denominator after the
first page.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from starlette.testclient import TestClient

from agent_bom.api import findings_count_cache
from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store
from agent_bom.api.models import JobStatus
from agent_bom.api.server import ScanJob, ScanRequest, app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_store
from tests._clock_helpers import recent
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())
    findings_count_cache.reset_findings_count_cache()


def _seed(tenant: str, *, scan_rows: int, bulk_rows: int) -> None:
    store = InMemoryComplianceHubStore()
    set_compliance_hub_store(store)
    bulk = [
        {
            "id": f"bulk-{idx:03d}",
            "severity": "medium",
            "cvss_score": float(idx % 10),
            "effective_reach_score": float(500 - idx),
            "origin": "bulk_ingest",
            "source": "test",
            "batch_id": "totals-batch",
        }
        for idx in range(bulk_rows)
    ]
    if bulk:
        store.add(tenant, bulk)
        store.upsert_current_batch(tenant, bulk, observed_at=recent("2026-07-19T00:00:00Z"), batch_id="totals-batch", source="test")
    set_job_store(InMemoryJobStore())
    if not scan_rows:
        return
    job = ScanJob(job_id=f"scan-job-{uuid4().hex}", tenant_id=tenant, created_at=recent("2026-07-19T10:00:00Z"), request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = recent("2026-07-19T10:01:00Z")
    job.result = {
        "findings": [
            {
                "id": f"scan-{idx:03d}",
                "vulnerability_id": f"CVE-2026-{idx:04d}",
                "severity": "high",
                "cvss_score": 5.0,
                "effective_reach_score": float(1000 - idx),
                "package": f"pkg-{idx}",
            }
            for idx in range(scan_rows)
        ]
    }
    _get_store().put(job)


def _walk(client: TestClient, headers: dict[str, str], query: str, *, cold_cache: bool) -> list[dict[str, Any]]:
    pages: list[dict[str, Any]] = []
    cursor = ""
    while len(pages) < 100:
        if cold_cache:
            findings_count_cache.reset_findings_count_cache()
        url = f"/v1/findings?{query}" + (f"&cursor={cursor}" if cursor else "")
        body = client.get(url, headers=headers).json()
        pages.append(body)
        if not body["has_more"]:
            return pages
        cursor = body["next_cursor"]
    raise AssertionError("cursor walk did not terminate")


def _assert_exact_every_page(pages: list[dict[str, Any]], expected: int) -> None:
    assert len(pages) > 2
    for number, page in enumerate(pages, start=1):
        assert page["total"] == expected, f"page {number} total {page['total']}"
        assert page["count_metadata"]["total_kind"] == "exact", f"page {number}"
    assert sum(len(page["findings"]) for page in pages) == expected


def test_merged_cursor_pages_keep_the_exact_total() -> None:
    tenant = f"totals-merged-{uuid4().hex}"
    _seed(tenant, scan_rows=9, bulk_rows=17)
    client = TestClient(app)
    for cold in (False, True):
        _assert_exact_every_page(_walk(client, proxy_headers(tenant=tenant), "limit=4", cold_cache=cold), 26)


def test_bulk_keyset_cursor_pages_keep_the_exact_total() -> None:
    tenant = f"totals-bulk-{uuid4().hex}"
    _seed(tenant, scan_rows=0, bulk_rows=17)
    client = TestClient(app)
    for cold in (False, True):
        _assert_exact_every_page(_walk(client, proxy_headers(tenant=tenant), "limit=4", cold_cache=cold), 17)


def test_severity_filter_cursor_pages_keep_the_exact_total() -> None:
    tenant = f"totals-severity-{uuid4().hex}"
    _seed(tenant, scan_rows=9, bulk_rows=17)
    client = TestClient(app)
    pages = _walk(client, proxy_headers(tenant=tenant), "limit=4&severity=medium", cold_cache=True)
    _assert_exact_every_page(pages, 17)


def test_approximate_cursor_page_never_runs_a_count_on_a_cold_cache() -> None:
    tenant = f"totals-approx-{uuid4().hex}"
    _seed(tenant, scan_rows=9, bulk_rows=17)
    client = TestClient(app)
    headers = proxy_headers(tenant=tenant)
    first = client.get("/v1/findings?limit=4", headers=headers).json()
    findings_count_cache.reset_findings_count_cache()
    body = client.get(f"/v1/findings?limit=4&approximate_total=true&cursor={first['next_cursor']}", headers=headers).json()
    assert body["total"] is None
    assert body["count_metadata"]["total_kind"] == "unknown"


def test_scoped_cursor_page_keeps_the_honest_marker() -> None:
    tenant = f"totals-scoped-{uuid4().hex}"
    _seed(tenant, scan_rows=9, bulk_rows=17)
    client = TestClient(app)
    headers = proxy_headers(tenant=tenant)
    first = client.get("/v1/findings?limit=4&provider=aws", headers=headers).json()
    if not first.get("next_cursor"):
        return
    body = client.get(f"/v1/findings?limit=4&provider=aws&cursor={first['next_cursor']}", headers=headers).json()
    kind = body["count_metadata"]["total_kind"]
    assert (body["total"] is None) == (kind == "unknown")
    assert kind != "exact" or body["total"] == first["total"]
