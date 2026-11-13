"""Custom Click group that renders help with categorized commands."""

from __future__ import annotations

from collections import OrderedDict
from difflib import get_close_matches

import click

from agent_bom.cli._lazy_commands import LazyCommands

# Define command categories and which commands belong to each.
# Order matters — first match wins, unlisted commands go to "Other".
COMMAND_CATEGORIES: OrderedDict[str, list[str]] = OrderedDict(
    [
        ("Get started", ["connect", "scan", "graph", "report", "up"]),
        (
            "Scanning",
            ["image", "fs", "iac", "sbom", "secrets", "code", "cloud", "skills", "ingest", "check", "verify", "manifest", "scanners"],
        ),
        ("First run and setup", ["quickstart", "doctor", "demo", "samples", "capabilities", "profiles", "completions", "upgrade"]),
        ("Graph and attack paths", ["graph-paths", "graph-correlate", "graph-evidence", "mesh"]),
        (
            "MCP and runtime",
            [
                "mcp",
                "where",
                "proxy",
                "watch",
                "audit",
                "activity",
                "runtime",
                "gateway",
                "firewall",
                "proxy-bootstrap",
                "sidecar-injector",
                "audit-drain-dlq",
            ],
        ),
        (
            "Findings and governance",
            [
                "findings",
                "compliance",
                "policy",
                "remediate",
                "verify-remediation",
                "campaigns",
                "ticket",
                "export",
                "attest",
                "trust",
                "identity",
                "cost",
                "fleet",
            ],
        ),
        ("Platform and admin", ["serve", "auth", "schedule", "db", "teardown", "self-audit", "plugins", "interactive"]),
    ]
)

CATEGORY_DESCRIPTIONS: dict[str, str] = {
    "Get started": "The front door: connect a source (read-only) → scan → graph → report. `up` runs the platform locally.",
    "Scanning": "Images, filesystems, IaC, SBOMs, secrets, code, cloud accounts, AI skills and single packages.",
    "First run and setup": "Guided first run, readiness checks, labelled sample data, profiles and upgrades.",
    "Graph and attack paths": "Ranked attack paths, snapshot correlation, graph history and live topology.",
    "MCP and runtime": "MCP discovery and servers, runtime proxy, gateway, firewall and session activity.",
    "Findings and governance": "Triage, compliance, policy, remediation, tickets, exports, trust, identity and cost.",
    "Platform and admin": "API and dashboard server, auth, schedules, vulnerability database and deployment.",
    "Other": "Additional commands that do not fit a primary workflow bucket.",
}

SHORT_HELP_LIMIT = 48


def _help_rows(group: click.Group, ctx: click.Context) -> dict[str, str]:
    """Visible command names and help lines; lazy groups answer from their static index."""
    commands = group.commands
    rows: dict[str, str] = {}
    for name in group.list_commands(ctx):
        if isinstance(commands, LazyCommands):
            help_text, hidden = commands.help_row(name, SHORT_HELP_LIMIT)
        else:
            cmd = group.get_command(ctx, name)
            if cmd is None or not isinstance(cmd, click.Command):
                continue
            help_text, hidden = cmd.get_short_help_str(limit=SHORT_HELP_LIMIT), cmd.hidden
        if not hidden:
            rows[name] = help_text
    return rows


class SuggestingGroup(click.Group):
    """A Click group that suggests nearby subcommands on typos."""

    def resolve_command(self, ctx: click.Context, args: list[str]):
        try:
            return super().resolve_command(ctx, args)
        except click.UsageError as exc:
            if args:
                suggestion = self._suggest_command(ctx, args[0])
                if suggestion and "No such command" in exc.message:
                    raise click.UsageError(f"{exc.message}\n\nDid you mean '{suggestion}'?", ctx=ctx) from exc
            raise

    def _suggest_command(self, ctx: click.Context, command_name: str) -> str | None:
        if isinstance(self.commands, LazyCommands):
            visible_commands = self.list_commands(ctx)
        else:
            visible_commands = [name for name in self.list_commands(ctx) if self.get_command(ctx, name) is not None]
        matches = get_close_matches(command_name, visible_commands, n=1, cutoff=0.62)
        return matches[0] if matches else None


class GroupedGroup(SuggestingGroup):
    """A Click group that displays commands organized by category.

    Pass ``command_categories`` to override the default category mapping.
    Each product (agent-bom, agent-shield, etc.) provides its own categories.
    """

    def __init__(self, *args, command_categories=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._command_categories = command_categories or COMMAND_CATEGORIES

    def format_commands(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        commands = _help_rows(self, ctx)
        if not commands:
            return

        placed: set[str] = set()
        for category, cmd_names in self._command_categories.items():
            rows = [(name, commands[name]) for name in cmd_names if name in commands and name not in placed]
            placed.update(name for name, _ in rows)
            if rows:
                self._write_section(formatter, category, rows)

        other = [(name, commands[name]) for name in sorted(commands) if name not in placed]
        if other:
            self._write_section(formatter, "Other", other)

    @staticmethod
    def _write_section(formatter: click.HelpFormatter, category: str, rows: list[tuple[str, str]]) -> None:
        with formatter.section(category):
            description = CATEGORY_DESCRIPTIONS.get(category)
            if description:
                formatter.write_text(description)
            formatter.write_dl(rows)

    def format_epilog(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        formatter.write_paragraph()
        formatter.write_text(
            "Navigation tips: get started with connect → scan → graph → report. New here? "
            "Run `agent-bom scan . -f html -o report.html` in a project, `agent-bom doctor` "
            "for readiness, or `agent-bom scan --demo --offline` for a labelled sample. `agent-bom COMMAND --help` lists a command's flags."
        )
