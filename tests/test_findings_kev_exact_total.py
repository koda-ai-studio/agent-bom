"""``?kev=`` reports an exact total, reconciling with the overview KEV count."""

from __future__ import annotations

import tempfile

from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, SQLiteComplianceHubStore, set_compliance_hub_store
from agent_bom.api.server import app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from tests._clock_helpers import recent
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_AUTH = proxy_headers(tenant="default")


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())


def _seed(count: int, kev_every: int) -> None:
    findings = [
        {
            "id": f"kev-total-{idx:04d}",
            "title": f"CVE-2026-{idx:04d} in pkg",
            "cve_id": f"CVE-2026-{idx:04d}",
            "severity": "high",
            "effective_reach_score": float(idx % 17),
            "is_kev": idx % kev_every == 0,
            "origin": "bulk_ingest",
            "source": "test",
            "batch_id": "batch-kev-total",
        }
        for idx in range(count)
    ]
    store = SQLiteComplianceHubStore(f"{tempfile.mkdtemp()}/kev_total.db")
    store.add("default", findings)
    store.upsert_current_batch("default", findings, observed_at=recent("2026-07-18T00:00:00Z"), batch_id="batch-kev-total", source="test")
    set_compliance_hub_store(store)
    set_job_store(InMemoryJobStore())


def test_kev_true_total_is_exact_across_pages() -> None:
    _seed(1_200, kev_every=3)
    client = TestClient(app)

    body = client.get("/v1/findings?kev=true&limit=50", headers=_AUTH).json()

    assert body["total"] == 400
    assert body.get("total_approximate", False) is False
    assert body["count_metadata"]["total_kind"] == "exact"
    assert len(body["findings"]) == 50 and all(row["is_kev"] for row in body["findings"])


def test_kev_false_total_is_the_exact_complement() -> None:
    _seed(1_200, kev_every=3)
    client = TestClient(app)

    body = client.get("/v1/findings?kev=false&limit=50", headers=_AUTH).json()

    assert body["total"] == 800
    assert body.get("total_approximate", False) is False
    assert body["count_metadata"]["total_kind"] == "exact"
