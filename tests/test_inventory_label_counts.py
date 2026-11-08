"""The console headline counts agents exactly as the report does, never below zero."""

from __future__ import annotations

import pytest

from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package, ServerSurface
from agent_bom.output.inventory_label import inventory_counts, inventory_subjects


def _repo_project(name: str = "project:repo") -> Agent:
    return Agent(
        name=name,
        agent_type=AgentType.CUSTOM,
        config_path="/src/repo",
        source="project",
        mcp_servers=[
            MCPServer(
                name="app",
                command="project",
                surface=ServerSurface.OTHER,
                packages=[Package(name="pyyaml", version="5.3", ecosystem="pypi")],
            )
        ],
    )


def _project_with_mcp_config() -> Agent:
    return Agent(
        name="project:configured",
        agent_type=AgentType.CUSTOM,
        config_path="/src/configured/.mcp.json",
        source="project-config",
        mcp_servers=[MCPServer(name="filesystem", command="npx", args=["-y", "@modelcontextprotocol/server-filesystem"])],
    )


def _host_agent() -> Agent:
    return Agent(
        name="claude-code",
        agent_type=AgentType.CLAUDE_CODE,
        config_path="/home/user/.claude.json",
        mcp_servers=[MCPServer(name="memory", command="npx", args=["-y", "@modelcontextprotocol/server-memory"])],
    )


@pytest.mark.parametrize(
    ("agents", "expected"),
    [
        ([], (0, 0)),
        ([_repo_project()], (0, 1)),
        ([_repo_project(), _repo_project("project:other")], (0, 2)),
        ([_host_agent()], (1, 0)),
        ([_host_agent(), _repo_project()], (1, 1)),
        ([_project_with_mcp_config()], (0, 1)),
        ([_project_with_mcp_config(), _repo_project(), _host_agent()], (1, 2)),
    ],
)
def test_inventory_counts_match_report_agents_and_never_go_negative(agents, expected) -> None:
    report = AIBOMReport(agents=agents)

    agent_count, project_count = inventory_counts(report)

    assert (agent_count, project_count) == expected
    assert agent_count >= 0 and project_count >= 0
    # Every agent the headline names is one the report counts; projects are the only difference.
    real_agents = [a for a in agents if a.counts_as_agent and not a.name.startswith("project:")]
    assert agent_count == len(real_agents) <= report.total_agents
    assert project_count == sum(1 for a in agents if a.name.startswith("project:"))


def test_bare_repository_headline_reads_one_project_not_minus_one_agents() -> None:
    headline = inventory_subjects(AIBOMReport(agents=[_repo_project()]), bold=False)

    assert headline == "1 project"
    assert "-" not in headline
