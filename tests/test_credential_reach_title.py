"""The credential-reach finding names the credential and the server it is reached through.

"AI agent can reach a credential or privileged tool: cursor" said nothing about
which credential, through which server; the reader had to open the evidence.
"""

from __future__ import annotations

from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, TransportType


def _report() -> AIBOMReport:
    github = MCPServer(
        name="github",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-github"],
        transport=TransportType.STDIO,
        env={"GITHUB_TOKEN": "ghp_x"},
    )
    agent = Agent(name="cursor", agent_type=AgentType.CURSOR, config_path="/home/u/.cursor/mcp.json", mcp_servers=[github])
    return AIBOMReport(agents=[agent])


def _reach_findings(report: AIBOMReport) -> list:
    from agent_bom.graph.scan_findings import surface_graph_derived_findings

    surface_graph_derived_findings(report, scan_id="s1", tenant_id="default")
    return [f for f in report.to_findings() if (f.evidence or {}).get("rule_id") == "AGENT_REACHES_PRIVILEGED"]


def test_credential_reach_title_names_server_and_credential() -> None:
    hits = _reach_findings(_report())
    assert len(hits) == 1
    assert hits[0].title == "AI agent can reach a credential or privileged tool: cursor → github → GITHUB_TOKEN"


def test_credential_reach_title_counts_additional_routes() -> None:
    report = _report()
    report.agents[0].mcp_servers.append(
        MCPServer(name="slack", command="npx", args=["-y", "@modelcontextprotocol/server-slack"], env={"SLACK_BOT_TOKEN": "x"})
    )
    title = _reach_findings(report)[0].title
    assert title.startswith("AI agent can reach a credential or privileged tool: cursor → github → GITHUB_TOKEN")
    assert title.endswith("(+ slack → SLACK_BOT_TOKEN)")
