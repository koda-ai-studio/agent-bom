"""Overview, posture and findings report one exact count at any size.

The row budgets are lowered so the bounded walks truncate the way they do at one
million rows; the store aggregate must keep every surface exact regardless.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api import finding_grouping, findings_count_cache, hub_overview_cache
from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore, reset_compliance_hub_store, set_compliance_hub_store
from agent_bom.api.finding_page_read import _merge_scan_groups
from agent_bom.api.hub_materialization import run_materialization_tick
from agent_bom.api.routes import overview as overview_routes
from agent_bom.api.server import app, set_job_store
from agent_bom.api.storage.finding_materialized import issue_group_id
from agent_bom.api.store import InMemoryJobStore
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

ROOT = Path(__file__).resolve().parents[1]
BANDS = ["critical", "high", "high", "medium", "medium", "medium", "low", "low", None, None]


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


@pytest.fixture(autouse=True)
def hub(tmp_path, monkeypatch) -> Any:
    monkeypatch.setenv("AGENT_BOM_OVERVIEW_CACHE_TTL_SECONDS", "0")
    monkeypatch.setenv("AGENT_BOM_HUB_OVERVIEW_CACHE_TTL_SECONDS", "0")
    reset_compliance_hub_store()
    store = SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    set_compliance_hub_store(store)
    set_job_store(InMemoryJobStore())
    hub_overview_cache.reset_hub_overview_cache()
    overview_routes._reset_overview_cache()
    findings_count_cache.reset_findings_count_cache()
    yield store
    reset_compliance_hub_store()
    set_job_store(InMemoryJobStore())
    hub_overview_cache.reset_hub_overview_cache()


def _client(tenant: str = "tenant-a") -> TestClient:
    client = TestClient(app)
    client.headers.update(proxy_headers(role="admin", tenant=tenant))
    return client


def _rows(count: int, *, prefix: str = "CVE-2098", kev_every: int = 0, long: bool = False) -> list[dict[str, Any]]:
    rows = []
    for i in range(count):
        row: dict[str, Any] = {
            "title": f"{prefix}-{i}",
            "vulnerability_id": f"{prefix}-{i}",
            "package": f"pkg{i}",
            "finding_type": "CVE",
            "location": f"srv/{prefix}/{i}/" + ("d/" * 200 if long else "") + "requirements.txt",
        }
        band = BANDS[i % len(BANDS)]
        if band:
            row["severity"] = band
        if kev_every and i % kev_every == 0:
            row["is_kev"] = True
        rows.append(row)
    return rows


def _push(client: TestClient, rows: list[dict[str, Any]], source: str = "test") -> None:
    response = client.post("/v1/findings/bulk", json={"findings": rows, "source": source})
    assert response.status_code == 201, response.text
    overview_routes._reset_overview_cache()


def test_kev_repro_counts_compressed_rows_on_every_surface() -> None:
    client = _client()
    short = [{**row, "is_kev": True} for row in _rows(5, prefix="CVE-2095")]
    long = [{**row, "is_kev": True} for row in _rows(5, prefix="CVE-2096", long=True)]
    _push(client, short, "short")
    _push(client, long, "long")

    counts = client.get("/v1/overview").json()["finding_counts"]
    listed = client.get("/v1/findings", params={"kev": "true", "limit": 50}).json()
    posture = client.get("/v1/posture/counts").json()

    assert (counts["kev"], counts["kev_approximate"]) == (10, False)
    assert listed["total"] == len(listed["findings"]) == 10
    assert all(row["is_kev"] is True for row in listed["findings"])
    assert posture["kev"] == 10
    assert posture["issues"]["kev"] == 10


def test_kev_counts_do_not_cross_tenants() -> None:
    first, second = _client("tenant-a"), _client("tenant-b")
    _push(first, _rows(4, kev_every=1, long=True))
    _push(second, _rows(4, long=True))

    assert first.get("/v1/overview").json()["finding_counts"]["kev"] == 4
    assert second.get("/v1/overview").json()["finding_counts"]["kev"] == 0
    assert second.get("/v1/findings", params={"kev": "true"}).json()["total"] == 0


@pytest.fixture
def small_budgets(monkeypatch) -> None:
    monkeypatch.setattr(finding_grouping, "_FINDING_GROUP_MAX_OCCURRENCES", 3)
    monkeypatch.setenv("AGENT_BOM_SCOPE_FILTER_SCAN_BUDGET", "2")


def test_headline_stays_exact_past_the_row_budget(small_budgets) -> None:
    client = _client()
    _push(client, _rows(10))

    body = client.get("/v1/overview").json()
    issues = body["issue_counts"]

    assert {key: issues[key] for key in ("critical", "high", "medium", "low", "unrated", "total")} == {
        "critical": 1,
        "high": 2,
        "medium": 3,
        "low": 2,
        "unrated": 2,
        "total": 10,
    }
    assert issues["approximate"] is False
    assert body["headline"]["basis"] == "issue_groups"
    assert (body["headline"]["critical"], body["headline"]["high"]) == (1, 2)
    assert body["posture"]["severity_basis"] == "issue_groups"
    assert body["posture"]["finding_total"] == 10
    assert "1 critical" in body["posture"]["summary"] and "2 high" in body["posture"]["summary"]
    assert client.get("/v1/posture/counts").json()["issues"]["total"] == 10


def test_total_never_shrinks_as_severe_rows_are_added(small_budgets) -> None:
    client = _client()
    _push(client, _rows(10))
    first = client.get("/v1/overview").json()["issue_counts"]
    _push(client, [{**row, "severity": "critical"} for row in _rows(20, prefix="CVE-2097")], "more")
    second = client.get("/v1/overview").json()["issue_counts"]

    assert second["total"] == first["total"] + 20
    assert second["medium"] == first["medium"] == 3
    assert second["low"] == first["low"] == 2


def test_grouped_findings_report_the_same_exact_counts(small_budgets) -> None:
    client = _client()
    _push(client, _rows(10, kev_every=5))

    page = client.get("/v1/findings", params={"group_occurrences": "true", "limit": 2, "include_facets": "true"}).json()

    assert page["total"] == 10
    assert "total_approximate" not in page
    assert page["count_metadata"]["total_kind"] == "exact"
    assert page["grouping"]["kev_issue_total"] == 2
    assert page["grouping"]["total_basis"] == "store_aggregate"
    assert page["facets"]["severity"]["medium"] == 3
    assert any("exact" in warning for warning in page["warnings"])
    filtered = client.get("/v1/findings", params={"group_occurrences": "true", "limit": 2, "severity": "medium"}).json()
    assert filtered["total"] == 3


def test_vuln_card_and_lanes_stay_exact_past_the_scan_budget(small_budgets) -> None:
    client = _client()
    _push(client, _rows(10))

    body = client.get("/v1/overview").json()

    assert (body["domains"]["vuln"]["metric"], body["domains"]["vuln"]["count_exact"]) == (10, True)
    lane = next(lane for lane in body["coverage"] if lane["domain"] == "vuln")
    assert (lane["count"], lane["count_exact"], lane["evidence_status"]) == (10, True, "complete")
    assert lane["severity"]["medium"] == 3


class _NoAggregates(SQLiteComplianceHubStore):
    def current_issue_group_counts(self, *args: Any, **kwargs: Any) -> None:
        return None


def test_bounded_walk_is_never_stated_as_the_headline(small_budgets, tmp_path) -> None:
    set_compliance_hub_store(_NoAggregates(str(tmp_path / "walk.db")))
    client = _client()
    _push(client, _rows(10))

    body = client.get("/v1/overview").json()
    posture = client.get("/v1/posture/counts").json()

    assert body["issue_counts"] is None
    assert body["headline"]["basis"] == "occurrences"
    assert body["posture"]["severity_basis"] == "finding_occurrences"
    assert body["finding_counts"]["medium"] == 3
    assert "3 medium" in body["posture"]["summary"] or "2 high" in body["posture"]["summary"]
    assert posture["issues"]["approximate"] is True


def test_pending_rows_label_kev_approximate_until_the_tick_finishes(hub) -> None:
    client = _client()
    _push(client, _rows(6, kev_every=1, long=True))
    hub._conn.execute("UPDATE hub_findings_current SET issue_group_id = NULL, kev_direct = 0, intel_ref = '', lens_mask = 0")
    hub._conn.commit()
    overview_routes._reset_overview_cache()
    hub_overview_cache.reset_hub_overview_cache()

    pending = client.get("/v1/overview").json()
    assert pending["finding_counts"]["kev_approximate"] is True
    listed = client.get("/v1/findings", params={"kev": "true", "limit": 50}).json()
    assert len(listed["findings"]) == 6

    assert run_materialization_tick() == 6
    overview_routes._reset_overview_cache()

    settled = client.get("/v1/overview").json()
    assert (settled["finding_counts"]["kev"], settled["finding_counts"]["kev_approximate"]) == (6, False)


def _counts(**values: int) -> dict[str, int]:
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "unrated": 0, "info": 0, "unknown": 0, "total": 0, "kev": 0, **values}


def test_scan_rows_merge_onto_hub_groups_without_double_counting() -> None:
    shared = {"id": "s1", "vulnerability_id": "CVE-2092-1", "package": "shared", "severity": "critical", "is_kev": True}
    fresh = {"id": "s2", "vulnerability_id": "CVE-2092-2", "package": "fresh", "severity": "low"}
    unrated = {"id": "s3", "vulnerability_id": "CVE-2092-3", "package": "plain"}
    known = {issue_group_id(shared): (3, False)}

    merged = _merge_scan_groups(
        _counts(medium=1, total=1), [shared, fresh, unrated], lambda ids: {k: v for k, v in known.items() if k in ids}
    )

    assert merged == _counts(critical=1, low=1, unrated=1, unknown=1, total=3, kev=1)


def test_a_write_on_another_replica_drops_the_cached_total() -> None:
    key = findings_count_cache.cache_key(tenant_id="t", severity=None, scan_id=None, origin="bulk_ingest")
    findings_count_cache.sync_tenant_revision("t", 1)
    findings_count_cache.set_cached_total(key, 227_000)
    findings_count_cache.sync_tenant_revision("t", 1)
    assert findings_count_cache.get_cached_total(key) == 227_000

    findings_count_cache.sync_tenant_revision("t", 2)
    assert findings_count_cache.get_cached_total(key) is None


# Reads of keys inside hub payloads are blind to compressed rows. Backfills of
# pre-codec columns and the SLA conflict guard (Python carries it first) remain.
_JSON_READ = re.compile(r"(payload->>?'|payload\s*#>>?|json_extract\((?:\w+\.)?payload|json_text\(dialect, ['\"]payload)")
_ALLOWED_PAYLOAD_JSON_READS = {
    "src/agent_bom/api/postgres_compliance_hub.py": 19,
    "src/agent_bom/api/storage/hub_schema.py": 11,
    "src/agent_bom/api/storage/hub_sqlite.py": 1,
    "src/agent_bom/api/storage/finding_ledger_writes.py": 5,
    "src/agent_bom/api/storage/finding_current_writes.py": 3,
    "src/agent_bom/api/storage/finding_materialized.py": 2,
}


def test_no_new_sql_reads_keys_inside_hub_payloads() -> None:
    found: dict[str, int] = {}
    for path in (ROOT / "src/agent_bom/api").rglob("*.py"):
        hits = sum(len(_JSON_READ.findall(line)) for line in path.read_text().splitlines())
        if hits:
            found[str(path.relative_to(ROOT))] = hits
    assert found == _ALLOWED_PAYLOAD_JSON_READS
