"""A scoped MCP audit: passive by default, explicit live discovery opt-in."""

from __future__ import annotations

import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import click


@click.command("audit")
@click.argument("path", type=click.Path(exists=True, file_okay=False), required=False, default=None)
@click.option("--live", is_flag=True, help="Connect to configured HTTP/SSE servers and list live descriptors.")
@click.option("--allow-command-execution", is_flag=True, help="With --live, also launch configured stdio server commands.")
@click.option(
    "--expected-capability",
    multiple=True,
    type=click.Choice(["read", "write", "delete", "execute", "network", "auth", "admin"]),
    help="Expected tool capability; repeat to define the operator profile. Omitted uses agent-type heuristics.",
)
@click.option("--timeout", type=click.FloatRange(0.1, 60), default=10.0, show_default=True)
@click.option("--format", "output_format", type=click.Choice(["console", "json", "sarif"]), default="console")
@click.option("--output", "output_path", type=click.Path(dir_okay=False), default=None)
def mcp_audit_cmd(
    path: str | None,
    live: bool,
    allow_command_execution: bool,
    expected_capability: tuple[str, ...],
    timeout: float,
    output_format: str,
    output_path: str | None,
) -> None:
    """Audit MCP descriptors, auth and agent permission settings.

    Without PATH, audits every supported MCP client configuration on this
    machine; with PATH, only the project or config directory named.

    No tools are invoked. Live mode uses existing MCP discovery (including
    bounded linked Apps metadata reads). Resource-body injection, rendered
    prompts and active authorization bypass are not assessed. Exit 1 means
    high/critical findings; exit 2 means no servers or incomplete live listing.
    """
    from agent_bom.cli import _mcp_audit_runtime as runtime

    if allow_command_execution and not live:
        raise click.UsageError("--allow-command-execution requires --live")
    try:
        with redirect_stdout(sys.stderr):
            agents = runtime.discovery.discover_all(project_dir=path)
        servers = [s for a in agents for s in a.mcp_servers if s.is_mcp_surface]
        intro = (
            runtime.mcp_introspect.introspect_servers_sync(servers, timeout=timeout, allow_stdio=allow_command_execution)
            if live and servers
            else None
        )
        audit = runtime.audit_mcp_agents(agents, introspection_report=intro, expected_capabilities=list(expected_capability) or None)
        findings = [*runtime.evaluate_mcp_auth_posture(agents), *runtime.evaluate_agent_permission_posture(agents)]
        report = runtime.AIBOMReport(agents=agents, findings=findings)
        report.enforcement_data = audit.to_dict()
        if intro:
            report.introspection_data = {"results": [r.to_dict() for r in intro.results], "warnings": intro.warnings}
        findings = report.to_findings()
        if output_format == "console":
            lines = [f"MCP security audit: {len(servers)} servers; {len(findings)} findings in inspected scope."]
            lines.extend(f"{f.severity.upper()}: {f.title}" for f in findings)
            lines.append(
                "Coverage: configuration/live descriptors only. Resource bodies, rendered prompts and auth bypass are not assessed."
            )
            text = "\n".join(lines) + "\n"
        else:
            text = json.dumps(runtime.to_json(report) if output_format == "json" else runtime.to_sarif(report), indent=2) + "\n"
        if output_path:
            Path(output_path).write_text(text)
        else:
            click.echo(text, nl=False)
    except (OSError, ValueError, RuntimeError, runtime.IntrospectionError) as exc:
        click.echo("Error: " + runtime.sanitize_error(exc, generic=True), err=True)
        raise click.exceptions.Exit(2) from None
    if any(f.severity.lower() in {"high", "critical"} for f in findings):
        raise click.exceptions.Exit(1)
    if not servers:
        click.echo("No MCP servers discovered; no clean verdict is available.", err=True)
        raise click.exceptions.Exit(2)
    if live and any(row[kind]["status"] != "inspected" for row in audit.coverage for kind in ("tools", "resources", "prompts")):
        raise click.exceptions.Exit(2)
