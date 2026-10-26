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
def graph_store(tmp_path):
    from agent_bom.api import stores as api_stores
    from agent_bom.api.graph_store import SQLiteGraphStore

    original = api_stores._graph_store
    graph = SQLiteGraphStore(tmp_path / "context-graph.db")
    api_stores.set_graph_store(graph)
    yield graph
    api_stores._graph_store = original


@pytest.fixture()
def store(graph_store):
    job_store = InMemoryJobStore()
    set_job_store(job_store)
    yield job_store
    set_job_store(None)


def _seed_estate_graph(graph_store, *, tenant: str, agent: str) -> None:
    from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
    from agent_bom.graph.types import EntityType, RelationshipType

    graph = UnifiedGraph(scan_id=f"estate-{tenant}", tenant_id=tenant)
    graph.add_node(UnifiedNode(id=f"agent:{agent}", entity_type=EntityType.AGENT, label=agent))
    graph.add_node(UnifiedNode(id=f"server:{agent}", entity_type=EntityType.SERVER, label=f"{agent}-server"))
    graph.add_edge(UnifiedEdge(source=f"agent:{agent}", target=f"server:{agent}", relationship=RelationshipType.USES))
    graph_store.save_graph(graph)


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


@pytest.mark.asyncio
async def test_another_tenants_estate_graph_is_never_returned(store, graph_store) -> None:
    _seed(store, tenant="default", scan_id="scan-a", agent="agent-a", day=1)
    _seed_estate_graph(graph_store, tenant="tenant-b", agent="estate-b")

    payload = await _call(tenant_id="default")
    assert payload["source"] == "persisted_snapshot"
    assert _agent_labels(payload) == {"agent-a"}
    assert "estate-b" not in json.dumps(payload)


@pytest.mark.asyncio
async def test_the_estate_graph_is_the_default_source(store, graph_store) -> None:
    """The graph REST serves for the tenant answers first, paged, with its own coverage."""
    _seed_estate_graph(graph_store, tenant="tenant-b", agent="estate-b")
    _seed_estate_graph(graph_store, tenant="default", agent="estate-a")

    payload = await _call(tenant_id="default")
    assert payload["source"] == "current_estate_graph"
    assert _agent_labels(payload) == {"estate-a"}
    assert payload["estate_coverage"]["current_estate_agents"] == 1
    assert payload["pagination"]["has_more"] is False
    assert payload["completeness"]["complete"] is True
    assert "estate-b" not in json.dumps(payload)


def _seed_dependency_chain(graph_store, *, length: int) -> None:
    from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
    from agent_bom.graph.types import EntityType, RelationshipType

    graph = UnifiedGraph(scan_id="estate-chain", tenant_id="default")
    graph.add_node(UnifiedNode(id="agent:chain", entity_type=EntityType.AGENT, label="chain-agent"))
    graph.add_node(UnifiedNode(id="server:chain", entity_type=EntityType.SERVER, label="chain-server"))
    graph.add_edge(UnifiedEdge(source="agent:chain", target="server:chain", relationship=RelationshipType.USES))
    previous = "server:chain"
    for index in range(length):
        package = f"pkg:npm:dep{index}@1.0.0"
        graph.add_node(
            UnifiedNode(
                id=package, entity_type=EntityType.PACKAGE, label=f"dep{index}@1.0.0", attributes={"version": "1.0.0", "ecosystem": "npm"}
            )
        )
        graph.add_edge(UnifiedEdge(source=previous, target=package, relationship=RelationshipType.DEPENDS_ON))
        previous = package
    graph.add_node(
        UnifiedNode(
            id="vuln:CVE-2026-0001",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-2026-0001",
            severity="high",
            attributes={"vulnerability_id": "CVE-2026-0001"},
        )
    )
    graph.add_edge(UnifiedEdge(source=previous, target="vuln:CVE-2026-0001", relationship=RelationshipType.VULNERABLE_TO))
    graph_store.save_graph(graph)


@pytest.mark.asyncio
async def test_transitive_dependencies_reach_their_advisories_within_the_holder_depth(store, graph_store) -> None:
    from agent_bom.graph.component_paths import MAX_HOLDER_DEPTH

    _seed_dependency_chain(graph_store, length=3)
    payload = await _call(tenant_id="default")
    assert payload["source"] == "current_estate_graph"
    labels = {node["label"] for node in payload["nodes"] if node["kind"] == "vulnerability"}
    assert labels == {"CVE-2026-0001"}, payload["nodes"]
    assert payload["completeness"]["complete"] is True

    _seed_dependency_chain(graph_store, length=MAX_HOLDER_DEPTH + 2)
    deep = await _call(tenant_id="default")
    assert not [node for node in deep["nodes"] if node["kind"] == "vulnerability"]
    assert deep["completeness"]["complete"] is False
    assert "depth" in deep["completeness"]["reason"]


def _seed_same_name_agents(graph_store) -> None:
    from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
    from agent_bom.graph.types import EntityType, RelationshipType

    graph = UnifiedGraph(scan_id="estate-twins", tenant_id="default")
    for suffix in ("laptop", "ci"):
        agent_id, server_id = f"agent:assistant-{suffix}", f"server:github-{suffix}"
        graph.add_node(
            UnifiedNode(
                id=agent_id, entity_type=EntityType.AGENT, label="assistant", attributes={"canonical_id": f"canon-assistant-{suffix}"}
            )
        )
        graph.add_node(UnifiedNode(id=server_id, entity_type=EntityType.SERVER, label=f"github-{suffix}"))
        graph.add_edge(UnifiedEdge(source=agent_id, target=server_id, relationship=RelationshipType.USES))
    graph_store.save_graph(graph)


@pytest.mark.asyncio
async def test_same_name_agents_stay_distinct_and_carry_graph_ids(store, graph_store) -> None:
    """Two agents labelled alike are two graph nodes; the context graph must not merge them."""
    _seed_same_name_agents(graph_store)

    payload = await _call(tenant_id="default")

    agents = [node for node in payload["nodes"] if node["kind"] == "agent"]
    assert sorted(node["id"] for node in agents) == ["agent:assistant-ci", "agent:assistant-laptop"]
    assert {node["label"] for node in agents} == {"assistant"}
    assert {node["metadata"]["canonical_id"] for node in agents} == {"canon-assistant-ci", "canon-assistant-laptop"}
    uses = {(edge["source"], edge["target"]) for edge in payload["edges"] if edge["kind"] == "uses"}
    servers = {node["id"]: node["label"] for node in payload["nodes"] if node["kind"] == "server"}
    owners = {servers[target]: source for source, target in uses}
    assert owners == {"github-laptop": "agent:assistant-laptop", "github-ci": "agent:assistant-ci"}
