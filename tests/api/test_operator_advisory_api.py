"""Operator advisories: tenant-scoped store and match-against-stored-inventory API."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.operator_advisory_store import InMemoryOperatorAdvisoryStore, SQLiteOperatorAdvisoryStore
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store, set_operator_advisory_store
from tests._clock_helpers import recent

ADVISORY = json.loads((Path(__file__).parents[1] / "fixtures" / "php2shell" / "operator-advisory.json").read_text())
BASE = "/v1/intel/operator-advisories"


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryOperatorAdvisoryStore()
    return SQLiteOperatorAdvisoryStore(str(tmp_path / "advisories.db"))


def test_store_is_tenant_isolated(store) -> None:
    store.put("tenant-a", ADVISORY)
    assert [row["id"] for row in store.list("tenant-a")] == ["CVE-2026-109618"]
    assert store.list("tenant-b") == []
    assert store.get("tenant-b", "CVE-2026-109618") is None
    assert store.delete("tenant-b", "CVE-2026-109618") is False
    assert store.get("tenant-a", "CVE-2026-109618") is not None
    with pytest.raises(ValueError):
        store.put("  ", ADVISORY)


def _job(tenant: str, php_version: str) -> ScanJob:
    package = {
        "name": "php",
        "version": php_version,
        "ecosystem": "generic",
        "purl": f"pkg:generic/php/php@{php_version}",
        "cpe": f"cpe:2.3:a:php:php:{php_version}:*:*:*:*:*:*:*",
    }
    return ScanJob(
        job_id=str(uuid.uuid4()),
        tenant_id=tenant,
        status=JobStatus.DONE,
        created_at=recent("2026-10-22T00:00:00Z"),
        completed_at=recent("2026-10-22T00:01:00Z"),
        request=ScanRequest(images=[f"php:{php_version}"]),
        result={"scan_id": f"scan-{tenant}", "agents": [{"name": "image", "mcp_servers": [{"name": "php", "packages": [package]}]}]},
    )


@pytest.fixture()
def api(monkeypatch: pytest.MonkeyPatch):
    jobs = InMemoryJobStore()
    jobs.put(_job("default", "8.3.30"))
    jobs.put(_job("other-tenant", "8.2.10"))
    set_job_store(jobs)
    set_operator_advisory_store(InMemoryOperatorAdvisoryStore())
    yield TestClient(app)
    set_operator_advisory_store(None)


def test_declare_then_match_against_stored_inventory(api: TestClient) -> None:
    created = api.post(BASE, json=ADVISORY)
    assert created.status_code == 201, created.text
    assert created.json()["provenance"] == "operator_advisory"

    assert [row["id"] for row in api.get(BASE).json()["advisories"]] == ["CVE-2026-109618"]

    body = api.get(f"{BASE}/CVE-2026-109618/matches").json()
    (finding,) = body["findings"]
    assert finding["provenance"] == "operator_advisory"
    assert finding["fixed_version"] == "8.3.36"
    assert finding["package"]["version"] == "8.3.30"
    assert finding["scan_id"] == "scan-default"
    assert body["complete"] is True
    assert body["reports_examined"] == 1


def test_matches_for_all_advisories_and_unknown_advisory(api: TestClient) -> None:
    api.post(BASE, json=ADVISORY)
    assert len(api.get(f"{BASE}/matches").json()["findings"]) == 1
    assert api.get(f"{BASE}/CVE-2099-0001/matches").status_code == 404


def test_invalid_advisory_is_rejected(api: TestClient) -> None:
    assert api.post(BASE, json={**ADVISORY, "severity": "apocalyptic"}).status_code == 422
    assert api.get(BASE).json()["advisories"] == []


def test_delete_advisory(api: TestClient) -> None:
    api.post(BASE, json=ADVISORY)
    assert api.delete(f"{BASE}/CVE-2026-109618").status_code == 204
    assert api.delete(f"{BASE}/CVE-2026-109618").status_code == 404
    assert api.get(BASE).json()["advisories"] == []
