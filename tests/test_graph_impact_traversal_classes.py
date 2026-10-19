"""Blast radius follows exploit and access edges, never containment or findings.

A reverse walk over every edge answered "what can reach this bucket?" with the
account, environment, org and provider that merely hold it, plus the
misconfigurations that describe it. None of those can act on the bucket. The
walk now follows the dependency, authority, exposure, runtime and derived
traversal classes; structural, finding, governance and correlation edges are
excluded and named in ``interpretation``. MCP ``graph_reach`` reads the same
walk, so both surfaces give one answer.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from agent_bom.api import stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

pytestmark = pytest.mark.graph_contract("warn")

E = EntityType
R = RelationshipType

_NODES = {
    "org:o": E.ORG,
    "account:a": E.ACCOUNT,
    "env:e": E.ENVIRONMENT,
    "provider:aws": E.PROVIDER,
    "data_store:bucket": E.DATA_STORE,
    "misconfig:public": E.MISCONFIGURATION,
    "misconfig:role-wildcard": E.MISCONFIGURATION,
    "role:reader": E.ROLE,
    "user:alice": E.USER,
    "agent:x": E.AGENT,
    "server:s": E.SERVER,
    "package:p": E.PACKAGE,
    "vuln:CVE-2026-0001": E.VULNERABILITY,
}

_EDGES = [
    ("org:o", "account:a", R.CONTAINS),
    ("account:a", "env:e", R.CONTAINS),
    ("account:a", "data_store:bucket", R.CONTAINS),
    ("env:e", "server:s", R.CONTAINS),
    ("provider:aws", "account:a", R.HOSTS),
    ("misconfig:public", "data_store:bucket", R.AFFECTS),
    ("misconfig:role-wildcard", "role:reader", R.AFFECTS),
    ("role:reader", "data_store:bucket", R.CAN_ACCESS),
    ("user:alice", "role:reader", R.ASSUMES),
    ("agent:x", "server:s", R.USES),
    ("server:s", "package:p", R.DEPENDS_ON),
    ("package:p", "vuln:CVE-2026-0001", R.VULNERABLE_TO),
]

_CONTEXT_TYPES = {"org", "account", "environment", "provider", "misconfiguration", "vulnerability"}


def _graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="impact-scan", tenant_id="default", created_at="2026-10-18T00:00:00+00:00")
    for node_id, kind in _NODES.items():
        graph.add_node(UnifiedNode(id=node_id, entity_type=kind, label=node_id))
    for source, target, rel in _EDGES:
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=rel))
    return graph


@pytest.fixture(params=[False, True], ids=["empty_prior_jobs", "retained_prior_jobs"])
def prior_job_store(request, monkeypatch):
    """Exercise the graph contract after either empty or populated app state."""
    jobs = InMemoryJobStore()
    if request.param:
        jobs.put(
            ScanJob(
                job_id="retained-job",
                tenant_id="default",
                request=ScanRequest(),
                status=JobStatus.DONE,
                created_at="2026-10-18T00:00:00+00:00",
                completed_at="2026-10-18T00:00:00+00:00",
                result={"scan_id": "retained-scan", "agents": [], "findings": []},
            )
        )
    monkeypatch.setattr(stores, "_store", jobs)
    return jobs


@pytest.fixture
def store(tmp_path, monkeypatch, prior_job_store):
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    monkeypatch.delenv("AGENT_BOM_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_BOM_MCP_TENANT_ID", raising=False)
    graph_store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    graph_store.save_graph(_graph())
    # Current-estate reads resolve the graph and scan-job stores together.
    monkeypatch.setattr(stores, "_store", InMemoryJobStore())
    monkeypatch.setattr(stores, "_graph_store", graph_store)
    yield graph_store


def _reach(store: SQLiteGraphStore, node_id: str, direction: str, **kwargs) -> dict:
    from agent_bom.mcp_tools.graph_reach import graph_reach_impl

    raw = asyncio.run(
        graph_reach_impl(
            node_id=node_id,
            direction=direction,
            limit=200,
            _get_graph_store=lambda: store,
            _truncate_response=lambda value: value,
            **kwargs,
        )
    )
    return json.loads(raw)


def test_impact_of_a_bucket_is_who_can_access_it_not_what_contains_it(store) -> None:
    body = TestClient(app).get("/v1/graph/impact", params={"node": "data_store:bucket"}).json()

    assert body["affected_nodes"] == ["role:reader", "user:alice"]
    assert body["affected_by_type"] == {"role": 1, "user": 1}
    assert not _CONTEXT_TYPES & set(body["affected_by_type"])
    assert body["affected_count"] == 2


def test_impact_of_a_cve_reaches_the_workloads_that_ship_it(store) -> None:
    """A finding root enters the graph through its own finding edges, then walks access."""
    body = TestClient(app).get("/v1/graph/impact", params={"node": "vuln:CVE-2026-0001"}).json()

    assert body["affected_nodes"] == ["agent:x", "package:p", "server:s"]
    assert body["max_depth_reached"] == 3


def test_impact_interpretation_names_the_classes_it_walked_and_excluded(store) -> None:
    interpretation = TestClient(app).get("/v1/graph/impact", params={"node": "data_store:bucket"}).json()["interpretation"]

    assert interpretation["traversal_classes"] == ["authority", "dependency", "derived", "exposure", "runtime"]
    assert interpretation["excluded_traversal_classes"] == ["correlation", "finding", "governance", "structural"]


def test_depth_one_impact_of_a_cve_reports_unwalked_ancestors(store) -> None:
    body = TestClient(app).get("/v1/graph/impact", params={"node": "vuln:CVE-2026-0001", "max_depth": 1}).json()

    assert body["affected_nodes"] == ["package:p"]
    assert body["completeness"]["reason"] == "depth_limit"


@pytest.mark.parametrize("node_id", ["data_store:bucket", "vuln:CVE-2026-0001", "agent:x", "role:reader"])
def test_mcp_reach_in_equals_rest_impact(store, node_id: str) -> None:
    rest = TestClient(app).get("/v1/graph/impact", params={"node": node_id}).json()
    mcp = _reach(store, node_id, "in")

    assert [item["id"] for item in mcp["items"]] == rest["affected_nodes"]
    assert mcp["total"] == rest["affected_count"]
    assert mcp["affected_by_type"] == rest["affected_by_type"]
    assert mcp["completeness"] == rest["completeness"]
    assert mcp["interpretation"]["traversal_classes"] == rest["interpretation"]["traversal_classes"]


def test_mcp_reach_out_walks_the_same_classes(store) -> None:
    out = _reach(store, "user:alice", "out")

    assert [item["id"] for item in out["items"]] == ["data_store:bucket", "role:reader"]
    assert out["interpretation"]["excluded_traversal_classes"] == ["correlation", "finding", "governance", "structural"]


@pytest.mark.parametrize("direction", ["in", "out"])
def test_reach_always_returns_total_even_when_the_walk_is_bounded(store, direction: str) -> None:
    node_id = "vuln:CVE-2026-0001" if direction == "in" else "agent:x"
    page = _reach(store, node_id, direction, max_depth=1)

    assert page["completeness"]["truncated"] is True
    assert page["completeness"]["reason"] == "depth_limit"
    assert "total" in page and page["total"] == len(page["items"]) == 1
    # Unknown, not missing: a bounded walk cannot know the full reach.
    assert "total" in page["completeness"] and page["completeness"]["total"] is None
    assert page["completeness"]["lower_bound"] == 1
