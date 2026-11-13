"""/v1/agents pages, filters, searches and sorts server-side at estate scale.

The Agents page must hold up at thousands of agents: the API returns one
bounded page plus the totals, facet counts and population summary the page
needs, and never another tenant's agents.
"""

from __future__ import annotations

import json
import time
import uuid

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient

import agent_bom.api.routes.discovery as discovery
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store
from tests._clock_helpers import recent
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

TENANT_A = "tenant-a"
TENANT_B = "tenant-b"
ESTATE_SIZE = 5_000
TYPES = ("cursor", "claude-code", "custom", "windsurf")
SOURCES = ("project", "fleet", "cloud")


def _server(index: int, *, packages: int, vulns: int, credentials: list[str]) -> dict:
    return {
        "name": f"srv-{index}",
        "command": "npx",
        "surface": "mcp-server",
        "transport": "sse" if index % 2 else "stdio",
        "packages": [
            {
                "name": f"pkg-{index}-{p}",
                "version": "1.0.0",
                "ecosystem": "npm" if p % 2 else "pypi",
                "vulnerabilities": [{"id": f"CVE-2026-{index}{p}{v}"} for v in range(vulns if p == 0 else 0)],
            }
            for p in range(packages)
        ],
        "tools": [],
        "credential_env_vars": credentials,
        "security_blocked": index % 97 == 0,
    }


def _agent(index: int, *, tenant: str = TENANT_A) -> dict:
    agent_type = TYPES[index % len(TYPES)]
    servers = [
        _server(index * 10 + s, packages=(index % 5) + 1, vulns=index % 3, credentials=[f"TOKEN_{index % 7}_API_KEY"] if s == 0 else [])
        for s in range((index % 4) + 1)
    ]
    canonical = f"{tenant}-agent-{index:05d}"
    return {
        "name": f"{tenant}-agent-{index:05d}",
        "agent_type": agent_type,
        "config_path": f"/work/{index}",
        "source": SOURCES[index % len(SOURCES)],
        "status": "installed-not-configured" if index % 10 == 0 else "configured",
        "canonical_id": canonical,
        "stable_id": canonical,
        "mcp_servers": servers if index % 10 else [],
    }


def _seed(store: InMemoryJobStore, tenant: str, agents: list[dict]) -> None:
    store.put(
        ScanJob(
            job_id=str(uuid.uuid4()),
            tenant_id=tenant,
            status=JobStatus.DONE,
            created_at=recent("2026-07-01T00:00:00Z"),
            completed_at=recent("2026-07-01T00:01:00Z"),
            request=ScanRequest(offline=True),
            result={"agents": agents, "blast_radius": []},
        )
    )


@pytest.fixture(scope="module")
def estate_agents() -> list[dict]:
    return [_agent(i) for i in range(ESTATE_SIZE)]


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch, estate_agents: list[dict]):
    for name in (
        "AGENT_BOM_DEMO_ESTATE",
        "AGENT_BOM_API_HOST_DISCOVERY_TENANT",
        "AGENT_BOM_API_LOCAL_PATH_SCANS",
        "AGENT_BOM_ENABLE_LOCAL_PATH_SCANS",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda: pytest.fail("host discovery must not run"))
    discovery._clear_agents_response_cache_for_tests()
    store = InMemoryJobStore()
    set_job_store(store)
    _seed(store, TENANT_A, estate_agents)
    _seed(store, TENANT_B, [_agent(i, tenant=TENANT_B) for i in range(3)])
    enable_trusted_proxy_env()
    yield TestClient(app)
    disable_trusted_proxy_env()
    discovery._clear_agents_response_cache_for_tests()


def _get(client: TestClient, query: str = "", tenant: str = TENANT_A):
    return client.get(f"/v1/agents{query}", headers=proxy_headers(role="viewer", tenant=tenant))


def _page(client: TestClient, query: str = "", tenant: str = TENANT_A) -> dict:
    response = _get(client, query, tenant)
    assert response.status_code == 200, response.text
    return response.json()


def test_a_limited_page_is_bounded_with_totals_and_a_cursor(client: TestClient) -> None:
    body = _page(client, "?limit=50")

    assert len(body["agents"]) == 50
    assert body["count"] == ESTATE_SIZE
    assert body["total"] == ESTATE_SIZE
    assert body["limit"] == 50
    assert body["offset"] == 0
    assert body["has_more"] is True
    assert body["next_cursor"] == "50"

    second = _page(client, f"?limit=50&cursor={body['next_cursor']}")
    assert second["offset"] == 50
    first_ids = {agent["canonical_id"] for agent in body["agents"]}
    assert first_ids.isdisjoint(agent["canonical_id"] for agent in second["agents"])

    last = _page(client, f"?limit=50&offset={ESTATE_SIZE - 10}")
    assert len(last["agents"]) == 10
    assert last["has_more"] is False
    assert last["next_cursor"] is None


def test_page_response_stays_small_and_fast_at_estate_scale(client: TestClient) -> None:
    _page(client, "?limit=50")  # warm the per-tenant cache

    started = time.perf_counter()
    response = _get(client, "?limit=50&sort=findings&order=desc&q=cursor")
    elapsed = time.perf_counter() - started

    assert response.status_code == 200
    assert len(response.json()["agents"]) == 50
    assert len(response.content) < 400_000
    assert elapsed < 1.5, f"cached page took {elapsed:.2f}s"


def test_limit_and_offset_are_bounded(client: TestClient) -> None:
    assert _get(client, "?limit=0").status_code == 422
    assert _get(client, "?limit=501").status_code == 422
    assert _get(client, "?offset=-1").status_code == 422
    assert _get(client, "?limit=10&cursor=abc").status_code == 422
    assert _get(client, "?sort=config_path").status_code == 422
    assert _get(client, "?order=sideways").status_code == 422
    assert _get(client, f"?q={'x' * 201}").status_code == 422
    assert len(_page(client, "?limit=500")["agents"]) == 500


def test_unbounded_cursor_error_does_not_echo_input(client: TestClient) -> None:
    response = _get(client, "?limit=10&cursor=%3Cscript%3E")

    assert response.status_code == 422
    assert "<script>" not in response.text


def test_search_matches_name_type_and_source(client: TestClient) -> None:
    by_type = _page(client, "?limit=500&q=claude-code")
    assert by_type["total"] == ESTATE_SIZE // len(TYPES)
    assert {agent["agent_type"] for agent in by_type["agents"]} == {"claude-code"}

    by_name = _page(client, "?limit=10&q=agent-00042")
    assert [agent["name"] for agent in by_name["agents"]] == ["tenant-a-agent-00042"]

    by_source = _page(client, "?limit=10&q=FLEET")
    assert by_source["total"] == len([i for i in range(ESTATE_SIZE) if SOURCES[i % 3] == "fleet"])


def test_filters_combine_and_facets_count_each_dimension(client: TestClient, estate_agents: list[dict]) -> None:
    body = _page(client, "?limit=10&type=cursor&type=windsurf&status=configured&source=project")

    expected = [
        a for a in estate_agents if a["agent_type"] in {"cursor", "windsurf"} and a["status"] == "configured" and a["source"] == "project"
    ]
    assert body["total"] == len(expected)
    assert all(agent["agent_type"] in {"cursor", "windsurf"} for agent in body["agents"])
    # A facet ignores its own selection, so the chips keep showing alternatives.
    type_facet = body["facets"]["type"]
    assert set(type_facet) == set(TYPES)
    assert type_facet["cursor"] == len(
        [a for a in estate_agents if a["agent_type"] == "cursor" and a["status"] == "configured" and a["source"] == "project"]
    )
    assert sum(body["facets"]["status"].values()) == len(
        [a for a in estate_agents if a["agent_type"] in {"cursor", "windsurf"} and a["source"] == "project"]
    )


def test_sort_by_numeric_columns_and_name(client: TestClient, estate_agents: list[dict]) -> None:
    def findings(agent: dict) -> int:
        return sum(len(p.get("vulnerabilities") or []) for s in agent["mcp_servers"] for p in s["packages"])

    by_findings = _page(client, "?limit=20&sort=findings&order=desc")["agents"]
    assert [findings(a) for a in by_findings] == sorted((findings(a) for a in by_findings), reverse=True)
    assert findings(by_findings[0]) == max(findings(a) for a in estate_agents)

    by_servers = _page(client, "?limit=20&sort=servers&order=asc")["agents"]
    assert all(len(a["mcp_servers"]) == 0 for a in by_servers)

    by_name = _page(client, "?limit=3&sort=name&order=desc")["agents"]
    assert [a["name"] for a in by_name] == ["tenant-a-agent-04999", "tenant-a-agent-04998", "tenant-a-agent-04997"]


def test_summary_describes_the_whole_population_not_the_page(client: TestClient, estate_agents: list[dict]) -> None:
    body = _page(client, "?limit=5&type=cursor")
    summary = body["summary"]

    servers = [s for a in estate_agents for s in a["mcp_servers"]]
    assert summary["agents"] == ESTATE_SIZE
    assert summary["configured"] == len([a for a in estate_agents if a["status"] == "configured"])
    assert summary["mcp_servers"] == len(servers)
    assert summary["packages"] == sum(len(s["packages"]) for s in servers)
    assert summary["unique_credentials"] == 7
    assert summary["blocked_servers"] == len([s for s in servers if s["security_blocked"]])
    assert summary["remote_servers"] == len([s for s in servers if s["transport"] == "sse"])
    assert summary["ecosystems"]["npm"] + summary["ecosystems"]["pypi"] == summary["packages"]


def test_second_tenant_never_sees_first_tenant_agents(client: TestClient) -> None:
    body = _page(client, "?limit=500&q=agent", tenant=TENANT_B)

    assert body["total"] == 3
    assert body["count"] == 3
    assert all(agent["name"].startswith("tenant-b-") for agent in body["agents"])
    assert body["summary"]["agents"] == 3
    assert _page(client, "?limit=10&q=tenant-a", tenant=TENANT_B)["total"] == 0


def test_legacy_call_without_params_still_returns_every_agent(client: TestClient) -> None:
    body = _page(client)

    assert len(body["agents"]) == ESTATE_SIZE
    assert body["count"] == ESTATE_SIZE
    assert body["total"] == ESTATE_SIZE
    assert body["has_more"] is False
    assert body["limit"] is None


def test_paged_rows_are_copies_of_the_cache(client: TestClient) -> None:
    first = _page(client, "?limit=1")
    json.dumps(first)
    again = _page(client, "?limit=1")
    assert again["agents"][0]["name"] == first["agents"][0]["name"]
