"""MCP ``context_graph`` answers from the tenant's persisted scan snapshot.

Live discovery reads the MCP server host's own agent configurations, which is a
different estate from the snapshot a tenant asked about; it runs only when the
caller asks for it explicitly.
"""

from __future__ import annotations

import json
import uuid

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store
from agent_bom.mcp_tools.analysis import context_graph_impl
from tests._clock_helpers import recent


def _agent(name: str) -> dict:
    return {
        "name": name,
        "agent_type": "custom",
        "config_path": f"/work/{name}",
        "source": "project",
        "canonical_id": f"project:{name}",
        "stable_id": f"project:{name}",
        "mcp_servers": [
            {
                "name": f"{name}-github",
                "command": "npx",
                "surface": "mcp-server",
                "packages": [{"name": "form-data", "version": "4.0.0", "ecosystem": "npm"}],
                "tools": [{"name": "create_issue"}],
                "credential_env_vars": ["GITHUB_PERSONAL_ACCESS_TOKEN"],
            }
        ],
    }


def _seed(store: InMemoryJobStore, *, tenant: str, scan_id: str, agent: str, day: int) -> None:
    store.put(
        ScanJob(
            job_id=str(uuid.uuid4()),
            tenant_id=tenant,
            status=JobStatus.DONE,
            created_at=recent(f"2026-07-{day:02d}T00:00:00Z"),
            completed_at=recent(f"2026-07-{day:02d}T00:01:00Z"),
            request=ScanRequest(offline=True),
            result={"scan_id": scan_id, "agents": [_agent(agent)], "blast_radius": []},
        )
    )


@pytest.fixture()
def store():
    job_store = InMemoryJobStore()
    set_job_store(job_store)
    yield job_store
    set_job_store(None)


def _forbidden_pipeline(*_args, **_kwargs):
    pytest.fail("context_graph must not run live host discovery unless asked")


def _agent_labels(payload: dict) -> set[str]:
    return {node["label"] for node in payload["nodes"] if node["kind"] == "agent"}


async def _call(**kwargs) -> dict:
    kwargs.setdefault("_run_scan_pipeline", _forbidden_pipeline)
    return json.loads(await context_graph_impl(_truncate_response=lambda value: value, **kwargs))


@pytest.mark.asyncio
async def test_default_reads_the_persisted_snapshot_not_the_host(store) -> None:
    _seed(store, tenant="default", scan_id="scan-a", agent="agent-a", day=1)

    payload = await _call()

    assert payload["source"] == "persisted_snapshot"
    assert payload["scope"] == {"tenant_id": "default", "scan_id": None, "scan_ids": ["scan-a"]}
    assert _agent_labels(payload) == {"agent-a"}
    assert {"nodes", "edges", "lateral_paths", "interaction_risks", "stats", "completeness"} <= payload.keys()


@pytest.mark.asyncio
async def test_scan_id_selects_that_snapshot(store) -> None:
    _seed(store, tenant="default", scan_id="scan-old", agent="agent-old", day=1)
    _seed(store, tenant="default", scan_id="scan-new", agent="agent-new", day=2)

    payload = await _call(scan_id="scan-old")

    assert payload["scope"]["scan_id"] == "scan-old"
    assert _agent_labels(payload) == {"agent-old"}


@pytest.mark.asyncio
async def test_other_tenant_snapshot_is_never_returned(store) -> None:
    _seed(store, tenant="tenant-b", scan_id="scan-b", agent="agent-b", day=1)

    payload = await _call(tenant_id="default")

    assert payload["error"]["category"] == "not_found"
    assert "live=true" in payload["error"]["message"]
    assert "agent-b" not in json.dumps(payload)


@pytest.mark.asyncio
async def test_missing_requested_scan_is_an_error_not_a_live_scan(store) -> None:
    _seed(store, tenant="default", scan_id="scan-a", agent="agent-a", day=1)

    payload = await _call(scan_id="scan-missing")

    assert "error" in payload
    assert payload["error"]["details"]["scan_id"] == "scan-missing"


@pytest.mark.asyncio
async def test_live_true_runs_host_discovery_and_says_so(store) -> None:
    from agent_bom.models import Agent, AgentType, MCPServer

    calls: list[object] = []

    async def _pipeline(config_path=None):
        calls.append(config_path)
        server = MCPServer(name="local-fs", command="npx")
        agent = Agent(name="laptop-agent", agent_type=AgentType.CUSTOM, config_path="/home/me", mcp_servers=[server])
        return [agent], [], [], []

    payload = await _call(live=True, _run_scan_pipeline=_pipeline)

    assert calls == [None]
    assert payload["source"] == "live_discovery"
    assert payload["scope"]["tenant_id"] is None
    assert _agent_labels(payload) == {"laptop-agent"}


@pytest.mark.asyncio
async def test_config_path_implies_live_discovery(store) -> None:
    calls: list[object] = []

    async def _pipeline(config_path=None):
        calls.append(config_path)
        return [], [], [], []

    payload = await _call(config_path="/tmp/cfg", _run_scan_pipeline=_pipeline)

    assert calls == ["/tmp/cfg"]
    assert "error" in payload
