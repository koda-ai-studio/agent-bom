"""/v1/agents backpressure sheds overload, not honest estate-scale builds.

An uncached 5,000-agent build measured median 807 ms and max 2.3 s on a
laptop, and slower runners pass the generic 2,500 ms budget. That budget let a
few honest builds open the process-wide ``discovery`` breaker and 429 every
tenant for the cooldown.
"""

from __future__ import annotations

import types

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient

import agent_bom.api.routes.discovery as discovery
import agent_bom.backpressure as backpressure
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store
from agent_bom.backpressure import BackpressureRejectedError, describe_backpressure_posture
from tests.api.test_agents_list_paging import ESTATE_SIZE, TENANT_A, _agent, _seed
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

# Roughly three times the slowest laptop build: what a slow shared runner sees.
SLOW_RUNNER_BUILD_MS = 7_000


@pytest.fixture()
def slow_runner_client(monkeypatch: pytest.MonkeyPatch):
    for name in ("AGENT_BOM_DEMO_ESTATE", "AGENT_BOM_API_HOST_DISCOVERY_TENANT", "AGENT_BOM_BACKPRESSURE_DISCOVERY_P99_MS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda: pytest.fail("host discovery must not run"))
    discovery._clear_agents_response_cache_for_tests()
    store = InMemoryJobStore()
    set_job_store(store)
    _seed(store, TENANT_A, [_agent(i) for i in range(ESTATE_SIZE)])
    built = discovery._build_agents_response(TENANT_A)
    assert built["count"] == ESTATE_SIZE

    clock = {"now": 0.0}
    fake_time = types.SimpleNamespace(monotonic=backpressure.time.monotonic, perf_counter=lambda: clock["now"])
    monkeypatch.setattr(backpressure, "time", fake_time)

    def honest_uncached_build(tenant_id, query=None):
        clock["now"] += SLOW_RUNNER_BUILD_MS / 1000
        return discovery.page_agents_response(built, query or discovery.LEGACY_AGENT_QUERY)

    monkeypatch.setattr(discovery, "_build_and_cache_agents_response", honest_uncached_build)
    enable_trusted_proxy_env()
    yield TestClient(app)
    disable_trusted_proxy_env()
    discovery._clear_agents_response_cache_for_tests()


def test_honest_estate_scale_builds_do_not_open_the_discovery_breaker(slow_runner_client: TestClient) -> None:
    headers = proxy_headers(role="viewer", tenant=TENANT_A)
    for attempt in range(40):
        response = slow_runner_client.get("/v1/agents?limit=50", headers=headers)
        assert response.status_code == 200, f"build {attempt}: {response.status_code} {response.text[:200]}"
        assert response.json()["count"] == ESTATE_SIZE

    posture = next(path for path in describe_backpressure_posture()["paths"] if path["path"] == "discovery")
    assert posture["state"] == "closed"
    assert posture["rejected"] == 0
    assert posture["completed"] == 40
    assert posture["p99_threshold_ms"] > SLOW_RUNNER_BUILD_MS


def test_a_pile_up_beyond_concurrency_still_sheds() -> None:
    controller = backpressure._controller_for("discovery")
    for _ in range(controller.max_concurrency):
        controller.try_enter()
    with pytest.raises(BackpressureRejectedError, match="concurrency_limit"):
        controller.try_enter()
    for _ in range(controller.max_concurrency):
        controller.exit(150.0)


def test_a_sustained_degraded_tail_still_opens_the_breaker() -> None:
    controller = backpressure._controller_for("discovery")
    for _ in range(controller.min_samples + 5):
        if controller.open_until_monotonic:
            break
        controller.try_enter()
        controller.exit(controller.p99_threshold_ms * 2)

    assert controller.last_trigger_reason == "p99_latency_threshold"
    with pytest.raises(BackpressureRejectedError):
        controller.try_enter()
