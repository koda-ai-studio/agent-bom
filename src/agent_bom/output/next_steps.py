"""Static next steps after a scan, shared by the console footer and the HTML report.

Plain text and links only: nothing here contacts a service or records usage.
"""

from __future__ import annotations

import shlex
from html import escape
from importlib.util import find_spec
from typing import Any, NamedTuple

REPO_URL = "https://github.com/koda-ai-studio/agent-bom"
ACTION_DOCS_URL = "https://koda-ai-studio.github.io/agent-bom/integrations/github-action/"
MCP_DOCS_URL = f"{REPO_URL}/blob/main/docs/MCP_SERVER.md"


class Hint(NamedTuple):
    label: str
    command: str
    url: str = ""


def dashboard_installed() -> bool:
    """Whether this environment has the API server the local dashboard runs on."""
    return all(find_spec(module) is not None for module in ("fastapi", "uvicorn"))


def _scanned_project(tokens: list[str]) -> str:
    """The project a scan's arguments name: the positional path, else ``--project``/``-p``, else ``.``."""
    if tokens and not tokens[0].startswith("-"):
        return tokens[0]
    for flag, value in zip(tokens, tokens[1:]):
        if flag in {"-p", "--project"}:
            return value
    return "."


def graph_dashboard_command(target: str = ".") -> str:
    """Command that persists a scan and serves its security graph in the local dashboard.

    The demo has no project to activate, so it opens the bundled sample graph;
    any other target is activated as a project and prints the server command.
    """
    tokens = shlex.split(target)
    offline = " --offline" if "--offline" in tokens else ""
    if "--demo" in tokens:
        command = f"agent-bom quickstart --run{offline} --open"
    else:
        command = f"agent-bom quickstart --project {shlex.quote(_scanned_project(tokens))} --run{offline}"
    return command if dashboard_installed() else f"uvx --from 'agent-bom[ui]' {command}"


def _has_findings(report: Any) -> bool:
    return bool(getattr(report, "blast_radii", None)) or bool(getattr(report, "total_vulnerabilities", 0))


def next_step_items(report: Any, *, target: str = ".", first_scan_of_target: bool = False) -> list[Hint]:
    """Next steps chosen from what the scan found."""
    items: list[Hint] = []
    if _has_findings(report):
        items.append(Hint("Gate pull requests on new findings", "uses: koda-ai-studio/agent-bom@v0", ACTION_DOCS_URL))
    if first_scan_of_target:
        items.append(Hint("Rerun later to see what changed since this scan", f"agent-bom scan {target or '.'}"))
    if getattr(report, "total_servers", 0) or getattr(report, "total_agents", 0):
        items.append(Hint("Ask your coding agent", "claude mcp add agent-bom -- uvx agent-bom mcp server", MCP_DOCS_URL))
        items.append(Hint("Alert on MCP config changes", "agent-bom watch"))
        items.append(Hint("Block risky installs in Claude Code", "/plugin install agent-bom-guard@agent-bom"))
    return items


def next_steps_html(report: Any) -> str:
    """Static "Next steps" block for the HTML report footer."""
    rows = []
    for item in next_step_items(report, first_scan_of_target=True):
        link = f' &middot; <a href="{escape(item.url)}">docs</a>' if item.url else ""
        rows.append(f"<li>{escape(item.label)}: <code>{escape(item.command)}</code>{link}</li>")
    rows.append(f'<li>Found it useful? <a href="{REPO_URL}">Star agent-bom on GitHub</a></li>')
    return f'<section class="next-steps" aria-label="Next steps"><strong>Next steps</strong><ul>{"".join(rows)}</ul></section>'


__all__ = [
    "ACTION_DOCS_URL",
    "MCP_DOCS_URL",
    "REPO_URL",
    "Hint",
    "dashboard_installed",
    "graph_dashboard_command",
    "next_step_items",
    "next_steps_html",
]
