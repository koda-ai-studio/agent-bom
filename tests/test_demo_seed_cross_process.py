"""The demo seed is visible to every process reading the same demo state, not only the seeding one."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent_bom.api import auth, stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.middleware import APIKeyMiddleware, TrustHeadersMiddleware
from agent_bom.api.routes import graph as graph_routes
from agent_bom.demo_estate import boot_seed
from tests.test_graph_tenant_scope_and_bounds import _path_graph

TENANT = "default"
_SEEDER = """
import sys, time
from agent_bom.demo_estate import boot_seed
boot_seed.mark_seed_started()
print("marked", flush=True)
time.sleep(float(sys.argv[1]))
if sys.argv[2] == "finish":
    boot_seed.clear_seed_marker()
"""


@pytest.fixture()
def store(tmp_path, monkeypatch):
    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    graph_store.save_graph(_path_graph(TENANT))
    monkeypatch.setattr(stores, "_graph_store", graph_store)
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", TENANT)
    assert not boot_seed.demo_estate_seeding()
    yield graph_store
    boot_seed.clear_seed_marker()


def _seeder(seconds: float, mode: str) -> subprocess.Popen[str]:
    proc = subprocess.Popen([sys.executable, "-c", _SEEDER, str(seconds), mode], stdout=subprocess.PIPE, text=True, env=dict(os.environ))
    assert proc.stdout is not None and proc.stdout.readline().strip() == "marked"
    return proc


def _mcp_exposure() -> dict:
    from agent_bom.mcp_server import _execute_tool_async
    from agent_bom.mcp_tools.graph import exposure_paths_impl

    raw = asyncio.run(_execute_tool_async("exposure_paths", exposure_paths_impl, tenant_id=TENANT, _truncate_response=lambda v: v))
    return json.loads(str(raw))


def test_out_of_process_mcp_refuses_while_another_process_seeds(store):
    seeder = _seeder(30, "finish")
    try:
        refused = _mcp_exposure()
        assert refused["error"]["details"]["reason"] == "current_estate_seeding", refused
        assert refused["error"]["details"]["retry_after_seconds"] == 2
        assert boot_seed.demo_estate_seeding("default") and not boot_seed.demo_estate_seeding("tenant-other")
    finally:
        seeder.kill()
        seeder.wait()


def test_marker_cleared_at_seed_end_serves_again(store):
    seeder = _seeder(0.2, "finish")
    assert seeder.wait(timeout=30) == 0
    served = _mcp_exposure()
    assert "error" not in served and served["paths"], served


def test_a_crashed_seeder_does_not_block_reads(store):
    seeder = _seeder(30, "crash")
    seeder.kill()
    seeder.wait()
    assert not boot_seed.demo_estate_seeding("default")
    served = _mcp_exposure()
    assert "error" not in served and served["paths"], served


def test_an_expired_marker_is_ignored(store, monkeypatch):
    boot_seed.mark_seed_started()
    assert boot_seed.demo_estate_seeding("default")
    monkeypatch.setattr(time, "time", lambda: boot_seed._marker_payload()["started_at"] + boot_seed.SEED_MARKER_TTL_SECONDS + 1)
    assert not boot_seed.demo_estate_seeding("default")


@pytest.fixture()
def empty_client(tmp_path, monkeypatch):
    from agent_bom.backpressure import reset_backpressure_for_tests

    reset_backpressure_for_tests()
    monkeypatch.setattr(stores, "_graph_store", SQLiteGraphStore(tmp_path / "empty.db"))
    keys = auth.KeyStore()
    monkeypatch.setattr(auth, "_key_store", keys)
    token, key = auth.create_api_key("tenant-a", auth.Role.VIEWER, tenant_id="tenant-a")
    keys.add(key)
    app = FastAPI()
    app.include_router(graph_routes.router, prefix="/v1")
    app.add_middleware(APIKeyMiddleware, api_key="", allow_unauthenticated=False)
    app.add_middleware(TrustHeadersMiddleware)
    boot_seed._boot_seed_done.clear()
    try:
        with TestClient(app, headers={"Authorization": f"Bearer {token}"}) as client:
            yield client
    finally:
        boot_seed._boot_seed_done.set()
        reset_backpressure_for_tests()


@pytest.mark.parametrize("path", ["/v1/graph/rollup", "/v1/graph/views/fix-first", "/v1/graph/clusters"])
def test_reads_before_the_first_snapshot_answer_seeding_with_retry(empty_client, path):
    refused = empty_client.get(path)
    assert refused.status_code == 503, refused.text
    assert refused.headers.get("Retry-After") == "2"
    assert "current_estate_seeding" in refused.text
    boot_seed._boot_seed_done.set()
    after = empty_client.get(path)
    assert after.status_code == 503 and "Graph snapshots not found" in after.text
