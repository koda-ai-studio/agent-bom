"""A repository's notebooks, workflows and manifests are inventory, not agents or MCP servers."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agent_bom.discovery.identity import consolidate_project_agents
from agent_bom.domain.mcp_model import FRAMEWORK_AGENTS_METADATA_KEY
from agent_bom.github_actions import scan_github_actions
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.scan_findings import attach_graph_derived_findings
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.jupyter import scan_jupyter_notebooks
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, MCPTool, Package, ServerSurface, Severity, Vulnerability
from agent_bom.output.agent_mesh import build_agent_mesh
from agent_bom.output.graph_evidence import graph_evidence_sections
from agent_bom.output.json_fmt import to_json

REACH_TITLE = "AI agent can reach a credential"


def _notebook(root: Path, name: str = "demo") -> Path:
    path = root / f"{name}.ipynb"
    source = 'import openai\nimport os\nkey = os.environ["OPENAI_API_KEY"]\n!pip install anthropic==0.3.0\n'
    path.write_text(json.dumps({"cells": [{"cell_type": "code", "source": [source]}], "nbformat": 4, "nbformat_minor": 5, "metadata": {}}))
    return path


def _workflow(root: Path) -> Path:
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True)
    path = workflows / "ci.yml"
    path.write_text(
        "name: ci\non: push\nenv:\n  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\n"
        "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pip install openai\n"
    )
    return path


def _project_agent(root: Path, *servers: MCPServer) -> Agent:
    return Agent(
        name=f"project:{root.name}",
        agent_type=AgentType.CUSTOM,
        config_path=str(root),
        source="project",
        mcp_servers=list(servers),
    )


def _manifest_server(root: Path, *packages: Package) -> MCPServer:
    return MCPServer(name=root.name, command="project", args=[str(root)], surface=ServerSurface.OTHER, packages=list(packages))


def _graph(report: AIBOMReport):
    graph = build_unified_graph_from_report(graph_evidence_sections(report))
    attach_graph_derived_findings(report, graph)
    return graph


def _types(graph) -> set[EntityType]:
    return {node.entity_type for node in graph.nodes.values()}


def _reach_findings(report: AIBOMReport) -> list:
    return [finding for finding in report.to_findings() if REACH_TITLE in finding.title]


def test_notebook_keeps_its_own_surface_and_is_not_an_mcp_server(tmp_path):
    _notebook(tmp_path)
    [agent], _ = scan_jupyter_notebooks(tmp_path)
    [server] = agent.mcp_servers
    assert server.surface == ServerSurface.NOTEBOOK
    assert not server.is_mcp_surface
    assert not server.counts_as_mcp_server
    assert {package.name for package in server.packages} >= {"openai", "anthropic"}
    assert "OPENAI_API_KEY" in server.env


def test_workflow_keeps_its_own_surface_and_is_not_an_mcp_server(tmp_path):
    _workflow(tmp_path)
    [agent], _ = scan_github_actions(str(tmp_path))
    [server] = agent.mcp_servers
    assert server.surface == ServerSurface.CI_WORKFLOW
    assert not server.is_mcp_surface
    assert not server.counts_as_mcp_server
    assert "OPENAI_API_KEY" in server.env


def test_library_repository_reports_no_agents_servers_or_credential_reach(tmp_path):
    _notebook(tmp_path)
    _workflow(tmp_path)
    notebooks, _ = scan_jupyter_notebooks(tmp_path)
    workflows, _ = scan_github_actions(str(tmp_path))
    vulnerable = Package(
        name="anthropic",
        version="0.3.0",
        ecosystem="pypi",
        vulnerabilities=[Vulnerability(id="CVE-2099-0001", summary="placeholder", severity=Severity.HIGH)],
    )
    notebooks[0].mcp_servers[0].packages = [vulnerable]
    manifest = _manifest_server(tmp_path, Package(name="requests", version="2.0.0", ecosystem="pypi"))
    agents = consolidate_project_agents([_project_agent(tmp_path, manifest), *notebooks, *workflows])
    report = AIBOMReport(agents=agents)

    assert report.total_agents == 0
    assert report.total_servers == 0
    assert report.has_mcp_context is False
    assert report.total_packages == 3

    graph = _graph(report)
    assert not _types(graph) & {EntityType.AGENT, EntityType.SERVER, EntityType.CREDENTIAL, EntityType.CREDENTIAL_REF, EntityType.PROVIDER}
    assert _reach_findings(report) == []

    summary = to_json(report)["summary"]
    assert (summary["total_agents"], summary["total_mcp_servers"]) == (0, 0)
    mesh = build_agent_mesh(to_json(report)["agents"])
    assert mesh["stats"]["total_agents"] == 0
    assert mesh["stats"]["total_servers"] == 0
    assert mesh["nodes"] == []
    assert to_json(report)["summary"]["installed_unconfigured_agents"] == 0

    notebook_node = next(node for node in graph.nodes.values() if node.dimensions.surface == "notebook")
    assert notebook_node.entity_type == EntityType.SOURCE_FILE
    assert notebook_node.label == "demo"
    package_ids = {
        node.id for node in graph.nodes.values() if node.entity_type == EntityType.PACKAGE and node.label.startswith("anthropic")
    }
    assert package_ids
    assert any(edge.source == notebook_node.id and edge.target in package_ids for edge in graph.edges)
    assert any(node.entity_type == EntityType.VULNERABILITY and "CVE-2099-0001" in node.label for node in graph.nodes.values())


def test_workflow_graph_keeps_ci_job_and_run_evidence(tmp_path):
    _workflow(tmp_path)
    workflows, _ = scan_github_actions(str(tmp_path))
    workflows[0].mcp_servers[0].tools = [MCPTool(name="OpenAI SDK", description="AI SDK used in run step")]
    report = AIBOMReport(agents=workflows)
    graph = _graph(report)
    node = next(node for node in graph.nodes.values() if node.dimensions.surface == "ci-workflow")
    assert node.entity_type == EntityType.SOURCE_FILE
    assert node.attributes["path"]
    assert [n.label for n in graph.nodes.values() if n.entity_type == EntityType.TOOL] == ["OpenAI SDK"]
    jobs = [n for n in graph.nodes.values() if n.entity_type == EntityType.CI_JOB]
    assert [job.label for job in jobs] == ["ci"]
    related = {(edge.source, edge.target, edge.relationship) for edge in graph.edges}
    assert (node.id, jobs[0].id, RelationshipType.DEFINES) in related
    tool = next(n for n in graph.nodes.values() if n.entity_type == EntityType.TOOL)
    assert (jobs[0].id, tool.id, RelationshipType.RUNS) in related


def test_plain_repository_is_drawn_as_a_repository_not_agent_to_server(tmp_path):
    manifest = _manifest_server(tmp_path, Package(name="requests", version="2.0.0", ecosystem="pypi"))
    ai_inventory = Agent(
        name="ai-inventory",
        agent_type=AgentType.CUSTOM,
        config_path=str(tmp_path),
        source="ai-inventory",
        metadata={"project_root": str(tmp_path)},
        mcp_servers=[
            MCPServer(
                name="ai-inventory",
                surface=ServerSurface.AI_INVENTORY,
                packages=[Package(name="openai", version="latest", ecosystem="pypi")],
            )
        ],
    )
    sast = Agent(
        name="sast:repo",
        agent_type=AgentType.CUSTOM,
        config_path=str(tmp_path),
        source="sast",
        metadata={"project_root": str(tmp_path)},
        mcp_servers=[
            MCPServer(name="sast:repo", surface=ServerSurface.SAST, packages=[Package(name="rule-pack", version="1", ecosystem="sast")])
        ],
    )
    report = AIBOMReport(agents=consolidate_project_agents([_project_agent(tmp_path, manifest), ai_inventory, sast]))

    assert report.total_agents == 0
    assert report.total_servers == 0
    assert report.total_packages == 3
    graph = _graph(report)
    assert EntityType.AGENT not in _types(graph)
    assert EntityType.SERVER not in _types(graph)
    assert EntityType.DIRECTORY in _types(graph)
    assert {"requests@2.0.0", "openai@latest"} <= {node.label for node in graph.nodes.values() if node.entity_type == EntityType.PACKAGE}


def test_real_mcp_configuration_in_a_repository_is_an_agent_with_a_server(tmp_path):
    manifest = _manifest_server(tmp_path, Package(name="requests", version="2.0.0", ecosystem="pypi"))
    configured = Agent(
        name=f"project:{tmp_path.name}",
        agent_type=AgentType.CUSTOM,
        config_path=str(tmp_path / ".mcp.json"),
        source="project-config",
        metadata={"project_root": str(tmp_path)},
        mcp_servers=[MCPServer(name="github", command="npx", args=["-y", "server-github@1.0.0"], env={"GITHUB_TOKEN": "***REDACTED***"})],
    )
    report = AIBOMReport(agents=consolidate_project_agents([_project_agent(tmp_path, manifest), configured]))

    assert report.total_agents == 1
    assert report.total_servers == 1
    graph = _graph(report)
    assert {EntityType.AGENT, EntityType.SERVER} <= _types(graph)
    assert [node.label for node in graph.nodes.values() if node.entity_type == EntityType.SERVER] == ["github"]
    assert any(node.entity_type == EntityType.DIRECTORY and node.label == tmp_path.name for node in graph.nodes.values())
    assert len(_reach_findings(report)) == 1


def test_real_agent_code_counts_as_one_agent_and_no_mcp_server(tmp_path):
    manifest = _manifest_server(tmp_path, Package(name="requests", version="2.0.0", ecosystem="pypi"))
    code_agent = Agent(
        name="langchain:react-agent",
        agent_type=AgentType.CUSTOM,
        config_path=str(tmp_path),
        source="python-agents",
        mcp_servers=[
            MCPServer(name="langchain:react-agent", command="python", surface=ServerSurface.OTHER, env={"OPENAI_API_KEY": "***REDACTED***"})
        ],
    )
    report = AIBOMReport(agents=consolidate_project_agents([_project_agent(tmp_path, manifest), code_agent]))

    assert report.total_agents == 1
    assert report.total_servers == 0
    graph = _graph(report)
    assert EntityType.AGENT in _types(graph)
    assert len(_reach_findings(report)) == 1


def test_framework_agents_found_in_source_keep_the_project_an_agent(tmp_path):
    manifest = _manifest_server(tmp_path, Package(name="langgraph", version="0.2.0", ecosystem="pypi"))
    ai_inventory = Agent(
        name="ai-inventory",
        agent_type=AgentType.CUSTOM,
        config_path=str(tmp_path),
        source="ai-inventory",
        metadata={"project_root": str(tmp_path), FRAMEWORK_AGENTS_METADATA_KEY: True},
        mcp_servers=[MCPServer(name="ai-inventory", surface=ServerSurface.AI_INVENTORY)],
    )
    report = AIBOMReport(agents=consolidate_project_agents([_project_agent(tmp_path, manifest), ai_inventory]))

    assert report.total_agents == 1
    assert report.total_servers == 0
    assert EntityType.AGENT in _types(_graph(report))
    assert EntityType.SERVER not in _types(_graph(report))


def test_scan_cli_on_a_library_checkout_reports_no_false_inventory(tmp_path):
    root = tmp_path / "library"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.0.0\n")
    _notebook(root)
    _workflow(root)
    target = tmp_path / "report.json"
    from agent_bom.cli import main

    result = CliRunner().invoke(main, ["scan", "-p", str(root), "--no-discover", "--no-scan", "-f", "json", "-o", str(target)])
    assert target.exists(), result.output
    report = json.loads(target.read_text())
    assert (report["summary"]["total_agents"], report["summary"]["total_mcp_servers"]) == (0, 0)
    assert not [row for row in report["findings"] if REACH_TITLE in str(row.get("title"))]
    names = {package["name"] for agent in report["agents"] for server in agent["mcp_servers"] for package in server["packages"]}
    assert {"requests", "openai", "anthropic"} <= names
    surfaces = {server["surface"] for agent in report["agents"] for server in agent["mcp_servers"]}
    assert {"notebook", "ci-workflow"} <= surfaces
