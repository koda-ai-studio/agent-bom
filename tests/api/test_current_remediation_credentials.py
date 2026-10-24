"""Current-estate remediation must count the credentials its findings expose."""

from __future__ import annotations

from agent_bom.api.remediation_view import current_remediation_response, remediation_finding_projection


def _row(**overrides):
    row = {
        "cve_id": "CVE-2023-32681",
        "package_name": "requests",
        "package_version": "2.28.0",
        "ecosystem": "pypi",
        "severity": "medium",
        "fixed_version": "2.31.0",
        "affected_agents": ["langchain-service"],
        "exposed_credentials": ["DATABASE_URL", "PINECONE_API_KEY"],
        "exposed_tools": ["query"],
    }
    row.update(overrides)
    return row


def test_projection_keeps_credential_and_tool_names_but_never_values():
    projected = remediation_finding_projection(_row(evidence={"env": {"DATABASE_URL": "postgres://user:hunter2@db/prod"}}))
    assert projected["exposed_credentials"] == ["DATABASE_URL", "PINECONE_API_KEY"]
    assert projected["exposed_tools"] == ["query"]
    assert "hunter2" not in repr(projected)


def test_projection_drops_values_that_look_like_secrets_not_names():
    projected = remediation_finding_projection(_row(exposed_credentials=["DATABASE_URL", "postgres://user:hunter2@db/prod"]))
    assert projected["exposed_credentials"] == ["DATABASE_URL"]


def test_current_plan_reports_the_credentials_each_package_exposes():
    rows = [
        remediation_finding_projection(_row()),
        remediation_finding_projection(_row(cve_id="CVE-2024-35195", exposed_credentials=["OPENAI_API_KEY"])),
    ]
    plan = current_remediation_response({"findings": rows, "completeness": {"status": "complete"}}).remediation_plan
    [item] = [entry for entry in plan if entry["package"] == "requests"]
    assert sorted(item["exposed_credentials"]) == ["DATABASE_URL", "OPENAI_API_KEY", "PINECONE_API_KEY"]


def test_projection_keeps_held_on_server_credential_names_but_never_values():
    held = ["DATABASE_URL", "PINECONE_API_KEY", "STRIPE_KEY", "postgres://user:hunter2@db/prod"]
    projected = remediation_finding_projection(_row(evidence={"server_credentials": held}))
    assert projected["evidence"]["server_credentials"] == ["DATABASE_URL", "PINECONE_API_KEY", "STRIPE_KEY"]
    assert "hunter2" not in repr(projected)


def test_current_plan_counts_credentials_held_on_server_apart_from_exposure():
    rows = [
        remediation_finding_projection(_row(evidence={"server_credentials": ["DATABASE_URL", "PINECONE_API_KEY", "STRIPE_KEY"]})),
        remediation_finding_projection(
            _row(cve_id="CVE-2024-35195", exposed_credentials=[], evidence={"server_credentials": ["AWS_ROLE"]})
        ),
    ]
    plan = current_remediation_response({"findings": rows, "completeness": {"status": "complete"}}).remediation_plan
    [item] = [entry for entry in plan if entry["package"] == "requests"]
    assert item["server_credentials"] == ["AWS_ROLE", "DATABASE_URL", "PINECONE_API_KEY", "STRIPE_KEY"]
    assert item["server_credential_count"] == 4
    assert sorted(item["exposed_credentials"]) == ["DATABASE_URL", "PINECONE_API_KEY"]


def test_current_plan_says_held_credentials_were_not_recorded_rather_than_zero():
    plan = current_remediation_response({"findings": [remediation_finding_projection(_row())], "completeness": {"status": "complete"}})
    [item] = plan.remediation_plan
    assert item["server_credentials"] is None
    assert item["server_credential_count"] is None


def _blast_radius():
    from agent_bom.models import Agent, AgentType, BlastRadius, MCPServer, Package, Severity, Vulnerability

    package = Package(name="requests", version="2.28.0", ecosystem="pypi")
    server = MCPServer(name="svc", command="python", env={"DATABASE_URL": "x", "STRIPE_KEY": "y"}, packages=[package])
    agent = Agent(name="a", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/a.json", mcp_servers=[server])
    return BlastRadius(
        vulnerability=Vulnerability(id="CVE-2023-32681", summary="s", severity=Severity.MEDIUM, fixed_version="2.31.0"),
        package=package,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=["DATABASE_URL"],
        exposed_tools=[],
        all_server_credentials=["DATABASE_URL", "STRIPE_KEY"],
    )


def test_scan_time_finding_records_every_credential_the_servers_hold():
    from agent_bom.finding import blast_radius_to_finding

    finding = blast_radius_to_finding(_blast_radius())
    assert finding.evidence["server_credentials"] == ["DATABASE_URL", "STRIPE_KEY"]
    assert finding.exposed_credentials == ["DATABASE_URL"]


def test_console_and_json_plan_label_both_credential_counts():
    import io

    from rich.console import Console

    from agent_bom import output as output_mod
    from agent_bom.finding import blast_radius_to_finding
    from agent_bom.models import AIBOMReport
    from agent_bom.output.console_render import print_remediation_plan
    from agent_bom.output.json_fmt import remediation_json

    br = _blast_radius()
    [item] = remediation_json([blast_radius_to_finding(br)], total_agents=1)
    assert item["exposed_credentials"] == ["DATABASE_URL"]
    assert item["server_credentials"] == ["DATABASE_URL", "STRIPE_KEY"]
    assert item["server_credential_count"] == 2

    buffer = io.StringIO()
    original = output_mod.console
    output_mod.console = Console(file=buffer, force_terminal=False, width=200, no_color=True)
    try:
        print_remediation_plan(AIBOMReport(agents=list(br.affected_agents), blast_radii=[br]))
    finally:
        output_mod.console = original
    text = buffer.getvalue()
    assert "credentials exposed by impact:  DATABASE_URL" in text
    assert "credentials on server:  2 (DATABASE_URL, STRIPE_KEY)" in text
