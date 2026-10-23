"""Seeded demo-estate API clients for the demo contract suites.

``demo_estate_client`` boots a fresh seed for every test. Use it for tests that
write, reseed, patch, or rely on a just-booted estate.

``shared_demo_estate_client`` boots one seed per module and serves it to every
read-only test in that module, with the same setup and teardown. The autouse
``reset_global_test_state`` still runs before each test: durable stores reopen
from the module's database files, but in-memory state (proxy ring buffers,
firewall decisions, the identity tile) is cleared, so tests reading it stay on
the per-test seed. A module must use one kind or the other: the API app is
process-global, so a per-test client inside a live shared one would restart it.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from starlette.testclient import TestClient

# The hosted-demo contract is anonymous viewer access.  Supplying an unattested
# role header is credential spoofing and must be rejected by the auth resolver.
VIEWER: dict[str, str] = {}

_active_seeds: list[Path] = []


def _model_stale_backpressure() -> None:
    from agent_bom.backpressure import _controller_for, reset_backpressure_for_tests

    # Model the stale process state that caused main CI's 429 regression; the
    # seed must reset it at its process-lifecycle boundary.
    reset_backpressure_for_tests()
    controller = _controller_for("findings")
    controller.open_until_monotonic = time.monotonic() + 60
    controller.last_trigger_reason = "p99_latency_threshold"


def _reset_process_seed_state() -> None:
    """Clear the process-global stores the demo bootstrap fills."""
    from agent_bom.api import blueprint_store as blueprint_store_mod
    from agent_bom.api import cost_store as cost_store_mod
    from agent_bom.api import stores as api_stores
    from agent_bom.api.campaign_store import set_campaign_store
    from agent_bom.api.routes.proxy import _reset_proxy_runtime_for_tests
    from agent_bom.api.skills_scan_store import set_skills_scan_store
    from agent_bom.cloud.side_scan_lifecycle import reset_side_scan_state_store
    from agent_bom.demo_estate.bootstrap import reset_daily_evidence_day, reset_demo_estate_bootstrap_status

    # Proxy ring buffers and the firewall decision store keep the seeded gateway
    # feed; blueprints and spend leaked into test_graph_governance_overlay
    # (`assert 6 == 1`) when pytest-randomly ordered it after a demo test.
    _reset_proxy_runtime_for_tests()
    api_stores._get_firewall_decision_store().reset()
    blueprint_store_mod.set_blueprint_store(None)
    cost_store_mod._COST_STORE = None
    set_campaign_store(None)
    set_skills_scan_store(None)
    reset_side_scan_state_store()
    reset_daily_evidence_day()
    reset_demo_estate_bootstrap_status()


@contextmanager
def seeded_demo_estate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[TestClient]:
    """Boot the API on a fresh demo seed under *tmp_path*; restore process state on exit."""
    if _active_seeds:
        raise RuntimeError(f"a seeded demo estate already serves this process from {_active_seeds[0]}; use one demo client kind per module")
    _model_stale_backpressure()

    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "demo-estate.db"))
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(tmp_path / "demo-graph.db"))

    from agent_bom.api import compliance_hub_store as hub_store_mod
    from agent_bom.api import server as api_server
    from agent_bom.api import stores as api_stores
    from agent_bom.api.compliance_hub_store import set_compliance_hub_store
    from agent_bom.api.findings_count_cache import reset_findings_count_cache
    from agent_bom.backpressure import reset_backpressure_for_tests
    from agent_bom.demo_estate.bootstrap import reset_demo_estate_bootstrap_status

    # Bootstrap/refresh tests control the seed state explicitly. A periodic
    # maintenance tick can consume their seed stubs and add another job when
    # coverage makes a test cross the minute boundary.
    async def no_periodic_maintenance() -> None:
        pass

    monkeypatch.setattr(api_server, "_cleanup_loop", no_periodic_maintenance)

    api_server._runtime_api_key_seeded = False
    api_server._shutting_down = False
    original_job_store = api_stores._store
    original_graph_store = api_stores._graph_store
    original_trend_store = api_stores._trend_store
    original_hub_store = hub_store_mod._HUB_STORE
    # Triage decisions live in the process-wide exception store; one left by another test changes view filtering.
    original_exception_store = api_stores._exception_store
    api_stores._exception_store = None
    api_stores._store = None
    api_stores._graph_store = None
    api_stores._trend_store = None
    set_compliance_hub_store(None)
    reset_findings_count_cache()
    reset_demo_estate_bootstrap_status()
    # Each TestClient instance represents a fresh API process.  The adaptive
    # controllers are process-global, so reset them at that lifecycle boundary.
    reset_backpressure_for_tests()

    _active_seeds.append(tmp_path)
    try:
        with TestClient(api_server.app) as client:
            from agent_bom.demo_estate.boot_seed import wait_for_demo_estate_boot_seed

            assert wait_for_demo_estate_boot_seed(600), "demo estate seed did not finish"
            yield client
    finally:
        _active_seeds.remove(tmp_path)
        api_stores._store = original_job_store
        api_stores._graph_store = original_graph_store
        api_stores._trend_store = original_trend_store
        set_compliance_hub_store(original_hub_store)
        reset_findings_count_cache()
        api_stores._exception_store = original_exception_store
        reset_backpressure_for_tests()
        _reset_process_seed_state()


@pytest.fixture()
def demo_estate_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[TestClient]:
    with seeded_demo_estate(monkeypatch, tmp_path) as client:
        yield client


@pytest.fixture(scope="module")
def _module_demo_estate(tmp_path_factory: pytest.TempPathFactory) -> Iterator[TestClient]:
    with pytest.MonkeyPatch.context() as monkeypatch, seeded_demo_estate(monkeypatch, tmp_path_factory.mktemp("demo-estate")) as client:
        yield client


@pytest.fixture()
def shared_demo_estate_client(_module_demo_estate: TestClient) -> TestClient:
    """One module-wide seed for read-only tests; adaptive backpressure restarts per test."""
    from agent_bom.backpressure import reset_backpressure_for_tests

    # A per-test client starts with fresh latency controllers; keep that, so a
    # slow read earlier in the module cannot turn a later read into a 429.
    reset_backpressure_for_tests()
    return _module_demo_estate


def demo_graph_get(client: TestClient, path: str, params: dict):
    """Honor bounded backpressure while checking topology, not host throughput."""
    for attempt in range(3):
        response = client.get(path, headers=VIEWER, params=params)
        if response.status_code != 429:
            return response
        detail = response.json().get("detail") or {}
        if not isinstance(detail, dict) or detail.get("reason") != "p99_latency_threshold":
            return response
        delay = int(response.headers.get("retry-after", "0"))
        assert 1 <= delay <= 30, response.text
        if attempt < 2:
            time.sleep(delay)
    return response
