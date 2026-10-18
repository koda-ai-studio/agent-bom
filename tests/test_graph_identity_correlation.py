"""Identity and correlation regressions: distinct entities stay distinct, one entity stays one node."""

from __future__ import annotations

from agent_bom.canonical_ids import canonical_mcp_server_id, mcp_server_graph_id_for
from agent_bom.discovery.config_parsers import parse_mcp_config
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.mcp_server_aliases import previous_mcp_server_graph_ids
from agent_bom.graph.types import EntityType
from agent_bom.models import Agent, AgentType, AIBOMReport
from agent_bom.output.json_fmt import to_json

CONFIG = "/home/u/.cursor/mcp.json"


def _agent(servers_cfg: dict) -> Agent:
    servers = parse_mcp_config({"mcpServers": servers_cfg}, CONFIG)
    return Agent(name="cursor", agent_type=AgentType.CURSOR, config_path=CONFIG, mcp_servers=servers)


def _ids(graph, entity: EntityType) -> list[str]:
    return sorted(n.id for n in graph.nodes.values() if n.entity_type == entity)


def test_same_launch_recipe_under_two_configured_names_stays_two_servers():
    recipe = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}
    agent = _agent(
        {
            "github-work": {**recipe, "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_work111111111111111111111111111111"}},
            "github-personal": {**recipe, "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_home222222222222222222222222222222"}},
        }
    )
    assert len({s.canonical_id for s in agent.mcp_servers}) == 2
    graph = build_unified_graph_from_report(to_json(AIBOMReport(agents=[agent])))
    assert len(_ids(graph, EntityType.SERVER)) == 2
    assert len(_ids(graph, EntityType.CREDENTIAL)) == 2


def test_rotating_secrets_and_settings_keeps_server_identity():
    def ids(url: str, env: dict) -> list[str]:
        agent = _agent({"remote": {"url": url}, "local": {"command": "npx", "args": ["-y", "@x/mcp"], "env": env}})
        return [mcp_server_graph_id_for(s, agent) for s in agent.mcp_servers]

    first = ids("https://mcp.example.com/sse?api_key=SECRET1&workspace=a", {"LOG_LEVEL": "info", "API_TOKEN": "t1"})
    second = ids("https://mcp.example.com/sse?api_key=SECRET2&workspace=a", {"LOG_LEVEL": "debug", "API_TOKEN": "t2"})
    assert first == second
    assert ids("https://alice:hunter2@mcp.example.com/mcp", {}) == ids("https://alice:hunter3@mcp.example.com/mcp", {})
    # Non-secret routing still distinguishes endpoints.
    assert ids("https://mcp.example.com/sse?workspace=a", {}) != ids("https://mcp.example.com/sse?workspace=b", {})
    assert ids("https://alice@mcp.example.com/mcp", {}) != ids("https://bob@mcp.example.com/mcp", {})


def test_identity_is_not_derived_from_secret_material():
    with_secret = canonical_mcp_server_id("s", url="https://u:pw-one@mcp.example.com/x?token=abc")
    without = canonical_mcp_server_id("s", url="https://u@mcp.example.com/x")
    assert with_secret == without
    raw = canonical_mcp_server_id("s", "python", args=["a.py"], environment={"API_KEY": "one", "WORKSPACE": "w"})
    rotated = canonical_mcp_server_id("s", "python", args=["a.py"], environment={"API_KEY": "two", "WORKSPACE": "w"})
    assert raw == rotated


def test_previous_server_ids_alias_the_pre_name_identity():
    from agent_bom.graph.mcp_server_aliases import _previous_v3_mcp_server_id

    agent = _agent({"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"LOG_LEVEL": "info"}}})
    server = agent.mcp_servers[0]
    old = _previous_v3_mcp_server_id(server.name, server.command, args=server.args, working_dir=server.working_dir, environment=server.env)
    current = mcp_server_graph_id_for(server, agent)
    assert old not in current
    owner = current.rsplit(":", 1)[0]
    assert f"{owner}:{old}" in previous_mcp_server_graph_ids(server, agent)


def _project_agent_report() -> dict:
    agent_id = "523b8eb9-07dc-53cf-b7bd-2134d85f6247"
    return {
        "agents": [
            {
                "name": "project:app1",
                "stable_id": agent_id,
                "canonical_id": agent_id,
                "agent_type": "custom",
                "config_path": "<path:app1>",
                "source": "project",
                "mcp_servers": [],
            }
        ],
        "findings": [
            {
                "id": "1b9de22e-df24-5b81-8822-3cfffada43fe",
                "finding_type": "PROMPT_SECURITY",
                "source": "MCP_SCAN",
                "severity": "high",
                "title": "Missing mutual authentication on inter-agent edges",
                "asset": {
                    "name": "project:app1",
                    "asset_type": "agent",
                    "identifier": agent_id,
                    "stable_id": "3517bed7-6925-59ca-ac47-9af1ff474731",
                    "canonical_id": "3517bed7-6925-59ca-ac47-9af1ff474731",
                },
            }
        ],
    }


def _finding_neighbors(graph) -> set[str]:
    findings = {n.id for n in graph.nodes.values() if n.entity_type in (EntityType.MISCONFIGURATION, EntityType.VULNERABILITY)}
    assert findings
    return {e.source for e in graph.edges if e.target in findings} | {e.target for e in graph.edges if e.source in findings}


def test_pushed_credential_reach_finding_follows_the_rescoped_agent():
    import copy

    agent = _agent(
        {
            "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_TOKEN": "x"}},
            "db": {"command": "uvx", "args": ["mcp-server-postgres"], "env": {"DATABASE_PASSWORD": "y"}},
        }
    )
    local = to_json(AIBOMReport(agents=[agent]))
    local_graph = build_unified_graph_from_report(local)
    (local_agent,) = _ids(local_graph, EntityType.AGENT)
    local_creds = _ids(local_graph, EntityType.CREDENTIAL)
    assert len(local_creds) == 2
    pushed = copy.deepcopy(local)
    pushed["agents"][0]["source_id"] = "src-1"
    pushed["findings"] = [
        {
            "id": "669e1a60-d61a-5c08-933b-e9b0a72e8246",
            "finding_type": "COMBINATION",
            "source": "GRAPH_ANALYSIS",
            "severity": "high",
            "title": "Agent can reach privileged credentials",
            "node_id": local_agent,
            "asset": {
                "name": agent.name,
                "asset_type": "agent",
                "identifier": agent.stable_id,
                "canonical_id": "bde87b9a-9061-57b0-af16-a4ce39180cac",
            },
            "evidence": {"rule_id": "AGENT_REACHES_PRIVILEGED", "node_ids": [local_agent, *local_creds]},
        }
    ]
    graph = build_unified_graph_from_report(pushed, scan_id="s", tenant_id="t")
    agents = _ids(graph, EntityType.AGENT)
    assert agents == [f"agent:src-1:{local_agent.rsplit(':', 1)[1]}"]
    neighbors = _finding_neighbors(graph)
    assert agents[0] in neighbors
    assert set(_ids(graph, EntityType.CREDENTIAL)) <= neighbors


def _vercel_report(team: str, name: str = "same-name") -> dict:
    import httpx

    from agent_bom.cloud.vercel_inventory import collect_report

    project = {"id": "prj_Same", "accountId": team, "name": name, "gitForkProtection": False, "link": {"type": "github"}}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v10/projects":
            return httpx.Response(200, json={"projects": [project], "pagination": {"next": None}})
        deployment = {"uid": "dpl_Same", "projectId": "prj_Same", "teamId": team, "name": name, "state": "READY"}
        return httpx.Response(200, json={"deployments": [deployment], "pagination": {"next": None}})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        return collect_report(team_id=team, token="t", client=client)


def _merge(*reports: dict) -> dict:
    merged: dict = {"cloud_inventory": [], "findings": [], "coverage": []}
    for report in reports:
        for key in merged:
            merged[key] += report[key]
    return merged


def test_connector_findings_project_onto_the_connector_node_once():
    report = _merge(_vercel_report("team_A"), _vercel_report("team_B"))
    graph = build_unified_graph_from_report(report, scan_id="s", tenant_id="t")
    misconfigs = _ids(graph, EntityType.MISCONFIGURATION)
    assert len(misconfigs) == len(report["findings"]) == 2
    assert all(m.startswith("misconfig:vercel:") for m in misconfigs)
    assert sum(graph.stats()["severity_counts"].values()) == 2


def test_same_project_name_in_two_vercel_teams_is_two_applications():
    report = _merge(_vercel_report("team_A", name="Shop"), _vercel_report("team_B", name="shop"))
    graph = build_unified_graph_from_report(report, scan_id="s", tenant_id="t")
    apps = [n for n in graph.nodes.values() if n.entity_type == EntityType.APPLICATION]
    assert len(apps) == 2
    assert {n.label for n in apps} == {"Shop", "shop"}
    assert all(n.attributes["finding_count"] == 1 for n in apps)
    members = {app.id: {e.source for e in graph.edges if e.target == app.id} for app in apps}
    assert all(len(sources) == 1 and next(iter(sources)).startswith("misconfig:vercel:") for sources in members.values())
    assert members[apps[0].id] != members[apps[1].id]


def _canonical_count(*nodes) -> int:
    from agent_bom.graph.asset_canonicalize import canonicalize_assets
    from agent_bom.graph.container import UnifiedGraph

    graph = UnifiedGraph(tenant_id="t", scan_id="s")
    for node in nodes:
        graph.add_node(node)
    canonicalize_assets(graph)
    return len(graph.nodes)


def _snowflake_store(node_id: str, account: str, fqn: str):
    from agent_bom.graph.node import NodeDimensions, UnifiedNode

    return UnifiedNode(
        id=node_id,
        entity_type=EntityType.DATA_STORE,
        label=node_id,
        attributes={"account_id": account, "fqn": fqn},
        dimensions=NodeDimensions(cloud_provider="snowflake"),
    )


def test_snowflake_strong_key_follows_identifier_resolution():
    # Account spellings that differ in case are not proven aliases (see the canonicalization contract).
    assert _canonical_count(_snowflake_store("a", "AB123", "DB.S.T"), _snowflake_store("b", "ab123", "DB.S.T")) == 2
    # A quoted spelling resolves to the stored name; unquoted text resolves upper-case.
    assert _canonical_count(_snowflake_store("a", "AB123", "DB.S.T"), _snowflake_store("b", "AB123", 'db.s."T"')) == 1
    # Stored names are exact: a lower-case stored name can only come from a quoted identifier.
    assert _canonical_count(_snowflake_store("a", "AB123", "DB.S.T"), _snowflake_store("b", "AB123", "db.s.t")) == 2
    assert _canonical_count(_snowflake_store("a", "AB123", 'DB.S."Mixed"'), _snowflake_store("b", "AB123", "DB.S.MIXED")) == 2
    assert _canonical_count(_snowflake_store("a", "AB123", "DB.S.T"), _snowflake_store("b", "CD456", "DB.S.T")) == 2


def test_one_cve_on_two_package_versions_keeps_each_package_severity():
    rows = [
        {"vulnerability_id": "CVE-2022-0235", "severity": sev, "package_name": "node-fetch", "package_version": ver, "ecosystem": "npm"}
        for ver, sev in (("3.1.0", "high"), ("2.6.1", "medium"))
    ]
    graph = build_unified_graph_from_report({"agents": [], "blast_radius": rows})
    vuln = graph.nodes["vuln:CVE-2022-0235"]
    assert vuln.severity == "high"
    by_version = {
        graph.nodes[e.source].attributes.get("version"): e.evidence.get("severity")
        for e in graph.edges
        if e.target == vuln.id and graph.nodes[e.source].entity_type == EntityType.PACKAGE
    }
    assert by_version == {"3.1.0": "high", "2.6.1": "medium"}
    assert vuln.attributes["severity_by_package"] == {"node-fetch@2.6.1": "medium", "node-fetch@3.1.0": "high"}


def _gpu_container(name: str, image: str) -> dict:
    return {"name": name, "image": image, "resources": {"limits": {"nvidia.com/gpu": "1"}}}


def _gpu_agents(provider: str, containers: list[dict], *, context: str | None = None, project: str = "proj-1") -> list[Agent]:
    import json
    import subprocess
    from unittest.mock import patch

    pods = [{"metadata": {"namespace": "ns", "name": "p"}, "spec": {"containers": containers}}]
    completed = subprocess.CompletedProcess(["kubectl"], 0, json.dumps({"items": pods}), "")
    with patch("shutil.which", return_value="kubectl"), patch("subprocess.run", return_value=completed):
        if provider == "coreweave":
            from agent_bom.cloud.coreweave import _discover_gpu_pods

            return _discover_gpu_pods(context, None)[0]
        from agent_bom.cloud.nebius import _discover_k8s_gpu_pods

        return _discover_k8s_gpu_pods("k", project)[0]


def _gpu_counts(agents: list[Agent]) -> dict[str, int]:
    graph = build_unified_graph_from_report(to_json(AIBOMReport(agents=agents)))
    return {
        "agents": len(_ids(graph, EntityType.AGENT)),
        "servers": len(_ids(graph, EntityType.SERVER)),
        "pods": sum(1 for n in graph.nodes.values() if n.attributes.get("resource_type") == "gpu-pod"),
    }


def test_same_gpu_pod_in_two_nebius_projects_is_two_resources():
    single = [_gpu_container("trainer", "img/a:1")]
    agents = _gpu_agents("nebius", single, project="proj-a") + _gpu_agents("nebius", single, project="proj-b")
    assert _gpu_counts(agents) == {"agents": 2, "servers": 2, "pods": 2}


def test_same_gpu_pod_in_two_coreweave_contexts_is_two_resources():
    single = [_gpu_container("trainer", "img/a:1")]
    agents = _gpu_agents("coreweave", single, context="cluster-a") + _gpu_agents("coreweave", single, context="cluster-b")
    assert len({a.config_path for a in agents}) == 2
    assert _gpu_counts(agents) == {"agents": 2, "servers": 2, "pods": 2}


def test_multi_container_gpu_pod_is_one_agent_with_a_server_per_container():
    containers = [_gpu_container("trainer", "img/a:1"), _gpu_container("sidecar", "img/b:1")]
    for provider in ("nebius", "coreweave"):
        agents = _gpu_agents(provider, containers, context="ctx-a")
        assert len(agents) == 1, provider
        assert len(agents[0].mcp_servers) == 2, provider
        assert _gpu_counts(agents) == {"agents": 1, "servers": 2, "pods": 1}, provider


def _shared_cve_snapshot(*, tag_findings: bool) -> dict:
    from agent_bom.graph.container import AttackPath

    def path(agent: str, server: str, pkg: str, cred: str, finding: str) -> AttackPath:
        return AttackPath(
            source=agent,
            target="vuln:CVE-2023-4863",
            hops=[agent, server, pkg, "vuln:CVE-2023-4863"],
            credential_exposure=[cred],
            tool_exposure=[f"tool:{server}:read"],
            finding_ids=[finding] if tag_findings else [],
        )

    paths = [
        path("agent:demo-agent", "server:demo", "pkg:npm:sharp@0.32.0", "cred:server:demo:GCS_SERVICE_ACCOUNT_KEY", "f-demo"),
        path("agent:cfg-1:project%3Aproj", "server:proj", "pkg:npm:sharp@0.31.0", "cred:server:proj:APP_TOKEN", "f-proj"),
    ]
    return {"available": True, "scan_id": "s", "snapshot_generation": 1, "paths": paths, "complete": True}


def test_mcp_finding_exposure_stays_with_the_agent_that_reaches_the_package():
    from agent_bom.mcp_tools.finding_graph import project_finding

    row = {
        "id": "f-proj",
        "cve_id": "CVE-2023-4863",
        "finding_node_id": "vuln:CVE-2023-4863",
        "node_id": "pkg:npm:sharp@0.31.0",
        "affected_agents": ["project:proj"],
    }
    for tagged in (True, False):
        graph = project_finding(row, _shared_cve_snapshot(tag_findings=tagged))
        assert graph["credential_ids"] == ["cred:server:proj:APP_TOKEN"], tagged
        assert graph["reachers_from_agents"] == ["agent:cfg-1:project%3Aproj"], tagged
    by_agent_only = {"id": "x", "cve_id": "CVE-2023-4863", "affected_agents": ["demo-agent"]}
    assert project_finding(by_agent_only, _shared_cve_snapshot(tag_findings=False))["credential_ids"] == [
        "cred:server:demo:GCS_SERVICE_ACCOUNT_KEY"
    ]
    unrelated = {"id": "x", "cve_id": "CVE-2023-4863", "node_id": "pkg:npm:sharp@9.9.9"}
    assert project_finding(unrelated, _shared_cve_snapshot(tag_findings=False))["credential_ids"] == []


def test_server_child_aliases_are_derived_not_stored_per_child(tmp_path):
    import sqlite3

    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.graph.trace_projection import _Binder

    tools, agents = 20, 10
    server = {"name": "docs", "url": "https://docs.example/mcp", "tools": [{"name": f"t{i}"} for i in range(tools)]}
    report = {"agents": [{"name": f"a{i}", "mcp_servers": [server]} for i in range(agents)]}
    graph = build_unified_graph_from_report(report, scan_id="s1", tenant_id="t")
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(graph)
    with sqlite3.connect(tmp_path / "graph.db") as conn:
        rows = conn.execute("select entity_type, count(*) from graph_node_aliases group by 1").fetchall()
    counts = dict(rows)
    assert counts.get("tool", 0) == 0
    assert sum(counts.values()) <= 4 * (tools + agents)

    (server_id,) = _ids(graph, EntityType.SERVER)
    old_tool, current_tool = "tool:server:a3:docs:t7", f"tool:{server_id}:t7"
    assert current_tool in graph.nodes
    assert store.resolve_node_aliases(tenant_id="t", node_ids=[old_tool]) == {old_tool: current_tool}
    assert store.resolve_node_aliases(tenant_id="t", node_ids=[old_tool], scan_id="s1") == {old_tool: current_tool}
    assert store.resolve_node_aliases(tenant_id="t", node_ids=["tool:server:a3:docs:missing"]) == {}
    assert store.resolve_node_aliases(tenant_id="t", node_ids=[current_tool]) == {}
    assert _Binder(graph).node(old_tool).id == current_tool


def test_finding_row_on_scoped_project_agent_attaches_to_the_inventory_node():
    graph = build_unified_graph_from_report(_project_agent_report(), scan_id="s", tenant_id="t")
    agents = _ids(graph, EntityType.AGENT)
    assert len(agents) == 1
    assert agents[0].startswith("agent:cfg-")
    assert agents[0] in _finding_neighbors(graph)
