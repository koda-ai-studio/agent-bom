"""``agent-bom activity``: local read-only review of what coding agents did."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

import click

from agent_bom.cli._agent_mode import agent_mode_requested, emit_command_envelope
from agent_bom.runtime.agent_sessions.render import render_text

_RELATIVE = re.compile(r"^(\d{1,4})([dh])$")


def parse_since(value: str, *, now: datetime | None = None) -> datetime:
    """``30d``, ``12h`` or an ISO date/time (UTC when no offset is given)."""
    now = now or datetime.now(timezone.utc)
    text = value.strip().lower()
    match = _RELATIVE.match(text)
    if match:
        amount = max(1, int(match.group(1)))
        return now - (timedelta(days=amount) if match.group(2) == "d" else timedelta(hours=amount))
    try:
        moment = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise click.BadParameter("use a relative window like 30d or 12h, or an ISO date such as 2026-10-01") from exc
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


@click.command("activity")
@click.option("--since", "since_text", default="30d", show_default=True, help="Window start: 30d, 12h, or an ISO date.")
@click.option(
    "--project", type=click.Path(file_okay=False), default=None, help="Only sessions whose working directory is inside this path."
)
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text", show_default=True)
@click.option("--check-packages", is_flag=True, help="Look installed packages up for known vulnerabilities (network).")
def activity_cmd(since_text: str, project: str | None, output_format: str, check_packages: bool) -> None:
    """Review what Claude Code and Codex did: MCP usage, unused servers, risky actions.

    Reads local session history (~/.claude/projects, ~/.codex/sessions) on this
    machine only. Prompts and responses are never read into the report; command
    and path evidence is redacted. Nothing is sent unless --check-packages is set.
    """
    from agent_bom.runtime.agent_sessions.activity import build_activity_report

    report = build_activity_report(since=parse_since(since_text), project=project, check_packages=check_packages)
    if agent_mode_requested():
        confidence = {"level": "medium" if report["truncated"] else "high", "signals": ["local_session_history"]}
        emit_command_envelope(command="activity", data=report, summary=report["summary"]["counts"], confidence=confidence)
    elif output_format == "json":
        click.echo(json.dumps(report, indent=2, sort_keys=True))
    else:
        click.echo(render_text(report))
