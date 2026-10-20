"""/v1/agents and agent detail read stored scan history once per evidence revision.

Every stored job carries a full scan report (tens of MB on the demo estate).
These routes used to deserialize every job two or three times per request, and
their 30 s response cache was stamped before the build began, so a build that
ran past the TTL was already stale when stored. The contract now: one
evidence projection per durable job revision, shared by both routes, so a warm
read touches no report regardless of how many jobs are stored, and a new scan
is visible on the very next read.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient

import agent_bom.api.routes.discovery as discovery
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore, SQLiteJobStore
from agent_bom.api.stores import set_job_store
from tests._clock_helpers import recent

TENANT = "default"


class CountingSQLiteJobStore(SQLiteJobStore):
    def __init__(self, path: str) -> None:
        super().__init__(path)
        self.full_reads = 0

    def list_all(self, tenant_id: str | None = None, *, all_tenants: bool = False) -> list[ScanJob]:
        self.full_reads += 1
        return super().list_all(tenant_id, all_tenants=all_tenants)


def _agent(name: str, canonical_id: str) -> dict[str, Any]:
    return {
        "name": name,
        "agent_type": "custom",
        "config_path": f"/work/{name}",
        "source": "project",
        "canonical_id": canonical_id,
        "stable_id": canonical_id,
        "mcp_servers": [
            {
                "name": f"{name}-server",
                "canonical_id": f"{canonical_id}-server",
                "command": "npx",
                "url": "https://mcp.example.test/sse",
                "surface": "mcp-server",
                "packages": [{"name": "requests", "version": "2.28.0", "ecosystem": "pypi"}],
                "tools": [{"name": "run_chain"}],
                "credential_env_vars": ["OPENAI_API_KEY"],
            }
        ],
    }


def _blast(agent_id: str, vuln: str) -> dict[str, Any]:
    return {
        "vulnerability_id": vuln,
        "package": "requests@2.28.0",
        "severity": "high",
        "risk_score": 7.5,
        "affected_agent_ids": [agent_id],
        "affected_servers": ["svc-a-server"],
        "exposed_credentials": ["OPENAI_API_KEY"],
        "exposed_tools": ["run_chain"],
    }


def _job(day: int, vuln: str, *, tenant: str = TENANT) -> ScanJob:
    return ScanJob(
        job_id=str(uuid.uuid4()),
        tenant_id=tenant,
        status=JobStatus.DONE,
        created_at=recent(f"2026-07-{day:02d}T00:00:00Z"),
        completed_at=recent(f"2026-07-{day:02d}T00:01:00Z"),
        request=ScanRequest(offline=True),
        result={
            "scan_sources": ["project-scan"],
            "agents": [_agent("svc-a", "agent-a"), _agent("svc-b", "agent-b")],
            "blast_radius": [_blast("agent-a", vuln), _blast("agent-b", "CVE-2024-0002")],
        },
    )


@pytest.fixture(params=["scanned_estate", "showcase"])
def mode(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.delenv("AGENT_BOM_API_HOST_DISCOVERY_TENANT", raising=False)
    if request.param == "showcase":
        monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    else:
        monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    discovery._clear_agents_response_cache_for_tests()
    yield request.param
    discovery._clear_agents_response_cache_for_tests()


def _seeded(tmp_path, jobs: int) -> CountingSQLiteJobStore:
    store = CountingSQLiteJobStore(str(tmp_path / f"jobs-{jobs}.db"))
    for day in range(1, jobs + 1):
        store.put(_job(day % 28 + 1, "CVE-2023-32681"))
    store.put(_job(3, "CVE-2099-9999", tenant="tenant-b"))
    set_job_store(store)
    store.full_reads = 0
    return store


def _detail_path(mode: str, client: TestClient) -> str:
    if mode == "scanned_estate":
        return "/v1/agents/agent-a"
    first = client.get("/v1/agents?refresh=true").json()["agents"][0]
    return f"/v1/agents/{first['canonical_id']}"


@pytest.mark.parametrize("jobs", [2, 20])
def test_warm_reads_touch_no_stored_report_at_any_history_depth(mode: str, tmp_path, jobs: int) -> None:
    store = _seeded(tmp_path, jobs)
    client = TestClient(app)
    detail = _detail_path(mode, client)

    assert client.get("/v1/agents?refresh=true").status_code == 200
    assert client.get(detail).status_code == 200
    cold_reads = store.full_reads
    assert cold_reads <= 1, f"cold reads deserialized the history {cold_reads} times"

    store.full_reads = 0
    for _ in range(3):
        assert client.get("/v1/agents?refresh=true").status_code == 200
        assert client.get(detail).status_code == 200
    assert store.full_reads == 0


def test_a_new_scan_is_visible_on_the_next_read(mode: str, tmp_path) -> None:
    store = _seeded(tmp_path, 2)
    client = TestClient(app)
    detail = _detail_path(mode, client)
    before = client.get(detail).json()
    before_count = client.get("/v1/agents").json()["count"]

    store.put(_job(27, "CVE-2025-1111"))
    store.full_reads = 0

    after = client.get(detail).json()
    listed = client.get("/v1/agents").json()
    assert store.full_reads == 1, "a new revision is projected once and shared by both routes"
    assert listed["count"] == before_count
    if mode == "scanned_estate":
        ids = {row["vulnerability_id"] for row in after["blast_radius"]}
        assert ids == {"CVE-2025-1111"}
        assert ids != {row["vulnerability_id"] for row in before["blast_radius"]}


def test_cached_reads_equal_an_uncached_build(mode: str, tmp_path) -> None:
    store = _seeded(tmp_path, 3)
    client = TestClient(app)
    detail = _detail_path(mode, client)
    cached_list = client.get("/v1/agents?refresh=true").json()
    cached_detail = client.get(detail).json()

    memory = InMemoryJobStore()
    for job in store.list_all(tenant_id=TENANT) + store.list_all(tenant_id="tenant-b"):
        memory.put(job)
    set_job_store(memory)
    discovery._clear_agents_response_cache_for_tests()

    def _strip(body: Any) -> Any:
        if isinstance(body, dict):
            return {key: _strip(value) for key, value in body.items() if key not in {"discovered_at", "last_seen"}}
        if isinstance(body, list):
            return [_strip(value) for value in body]
        return body

    assert _strip(client.get("/v1/agents?refresh=true").json()) == _strip(cached_list)
    assert _strip(client.get(detail).json()) == _strip(cached_detail)


def test_the_projection_never_crosses_tenants(mode: str, tmp_path) -> None:
    _seeded(tmp_path, 2)
    client = TestClient(app)
    client.get("/v1/agents?refresh=true")
    body = client.get(_detail_path(mode, client)).json()

    assert body["blast_radius"] or mode == "showcase"
    assert "CVE-2099-9999" not in {row.get("vulnerability_id") for row in body["blast_radius"]}
