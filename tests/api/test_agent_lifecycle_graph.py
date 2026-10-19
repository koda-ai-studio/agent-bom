from copy import deepcopy

import pytest
import pytest_asyncio
from starlette.requests import Request

from agent_bom.api.routes import discovery


def agent_fixture():
    vuln = {"id": "CVE-2026-1000", "severity": "high", "summary": "Fixture"}
    package = {"name": "shared", "version": "1.0", "ecosystem": "npm", "vulnerabilities": [vuln]}
    return {
        "name": "agent",
        "agent_type": "custom",
        "mcp_servers": [
            {
                "name": "same",
                "url": "https://one.example/mcp",
                "tools": [{"name": f"tool-{i}"} for i in range(12)],
                "credential_env_vars": ["API_TOKEN"],
                "packages": [package],
            },
            {
                "name": "same",
                "url": "https://two.example/mcp",
                "tools": [],
                "credential_env_vars": ["API_TOKEN"],
                "packages": [deepcopy(package), {**deepcopy(package), "ecosystem": "pypi"}],
            },
        ],
    }


@pytest_asyncio.fixture
async def lifecycle(monkeypatch):
    async def detail(*args):
        return {"agent": agent_fixture(), "summary": {}}

    monkeypatch.setattr(discovery, "get_agent_detail", detail)
    return await discovery.get_agent_lifecycle(
        Request({"type": "http", "headers": [], "state": {"tenant_id": "lifecycle-fixture"}}), "agent"
    )


@pytest.mark.asyncio
async def test_lifecycle_ids_unique(lifecycle):
    ids = [n["id"] for n in lifecycle["nodes"]]
    assert len(ids) == len(set(ids))


@pytest.mark.asyncio
async def test_lifecycle_all_tools(lifecycle):
    assert len([n for n in lifecycle["nodes"] if n["data"]["nodeType"] == "tool"]) == 12


@pytest.mark.asyncio
async def test_lifecycle_shared_packages_keep_all_relationships(lifecycle):
    package_ids = {n["id"] for n in lifecycle["nodes"] if n["data"]["nodeType"] == "package"}
    assert len(package_ids) == 2
    assert len([e for e in lifecycle["edges"] if e["target"] in package_ids]) == 3


@pytest.mark.asyncio
async def test_lifecycle_edges_carry_receipts(lifecycle):
    assert all(e.get("data", {}).get("relationship") and e["data"].get("evidence") for e in lifecycle["edges"])


@pytest.mark.asyncio
async def test_lifecycle_counts_and_sqlite_export_reconcile(lifecycle, tmp_path):
    import json
    from collections import Counter

    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.graph.container import UnifiedGraph

    graph = UnifiedGraph.from_dict(lifecycle["graph"])
    # This derived inventory has no persisted scan. Name only the replay fixture.
    assert graph.scan_id == ""
    graph.scan_id = "lifecycle-replay-fixture"
    store = SQLiteGraphStore(tmp_path / "lifecycle.db")
    store.save_graph(graph)
    loaded = store.load_graph(tenant_id="lifecycle-fixture", scan_id=graph.scan_id)
    assert set(loaded.nodes) == set(graph.nodes)
    assert {edge.id for edge in loaded.edges} == {edge.id for edge in graph.edges}
    assert len({edge.id for edge in graph.edges}) == len(graph.edges)
    counts = Counter(node["data"]["nodeType"] for node in lifecycle["nodes"])
    for kind, key in (
        ("server", "servers"),
        ("package", "packages"),
        ("tool", "tools"),
        ("credential", "credentials"),
        ("cve", "vulnerabilities"),
    ):
        assert lifecycle["stats"][f"total_{key}"] == counts[kind]
    assert lifecycle["stats"]["total_credentials"] == 2
    assert lifecycle["stats"]["total_vulnerabilities"] == 1
    assert len([edge for edge in graph.edges if edge.relationship.value == "vulnerable_to"]) == 2
    exported = json.loads(json.dumps(lifecycle))
    by_id = {edge["id"]: edge for edge in exported["graph"]["edges"]}
    assert all(edge["data"] == by_id[edge["id"]] for edge in exported["edges"])
    assert all(edge["data"]["evidence"].get("tier") == "static_scan" for edge in exported["edges"])
    assert not any(edge.get("animated") for edge in exported["edges"])


def test_lifecycle_never_exposes_credential_values():
    import json

    from agent_bom.graph.lifecycle import agent_lifecycle_view

    agent = agent_fixture()
    agent["mcp_servers"][0]["env"] = {"API_TOKEN": "fixture-value-never-export"}
    view = agent_lifecycle_view(agent, tenant_id="tenant-other")
    assert view["graph"]["tenant_id"] == "tenant-other"
    assert "fixture-value-never-export" not in json.dumps(view)


@pytest.mark.asyncio
async def test_lifecycle_inventory_does_not_derive_exploitation_paths(lifecycle):
    assert not lifecycle["graph"]["attack_paths"]
    assert not any(edge["relationship"] == "exploitable_via" for edge in lifecycle["graph"]["edges"])
    # The owning inventory projector retains conservative credential/tool links
    # with their uncertainty receipts; the default UI excludes these links.
    assert all(
        edge["evidence"].get("mapping_method") == "server_scope_conservative"
        for edge in lifecycle["graph"]["edges"]
        if edge["relationship"] == "reaches_tool"
    )


@pytest.mark.asyncio
async def test_lifecycle_counts_the_advisories_the_agent_detail_reports(monkeypatch):
    """Inventory packages carry no vulnerability list; the detail's blast rows do."""
    agent = agent_fixture()
    for server in agent["mcp_servers"]:
        for package in server["packages"]:
            package["vulnerabilities"] = []
    blast = [
        {
            "vulnerability_id": "CVE-2023-36258",
            "package_name": "shared",
            "package_version": "1.0",
            "ecosystem": "npm",
            "severity": "critical",
            "affected_servers": ["same"],
        },
        {
            "vulnerability_id": "CVE-2026-2000",
            "package_name": "shared",
            "package_version": "1.0",
            "ecosystem": "pypi",
            "severity": "medium",
            "affected_servers": [],
        },
        {
            "vulnerability_id": "CVE-2026-3000",
            "package_name": "elsewhere",
            "package_version": "9.9",
            "ecosystem": "npm",
            "severity": "high",
            "affected_servers": ["same"],
        },
    ]

    async def detail(*args):
        return {"agent": agent, "summary": {"total_vulnerabilities": 3}, "blast_radius": blast}

    monkeypatch.setattr(discovery, "get_agent_detail", detail)
    view = await discovery.get_agent_lifecycle(
        Request({"type": "http", "headers": [], "state": {"tenant_id": "lifecycle-fixture"}}), "agent"
    )
    advisories = {n["data"]["label"] for n in view["nodes"] if n["data"]["nodeType"] == "cve"}
    assert advisories == {"CVE-2023-36258", "CVE-2026-2000"}
    assert view["stats"]["total_vulnerabilities"] == 2
    assert view["stats"]["severity_breakdown"]["critical"] == 1
    # The detail rows are not mutated into the agent inventory the caller holds.
    assert all(not package["vulnerabilities"] for server in agent["mcp_servers"] for package in server["packages"])
