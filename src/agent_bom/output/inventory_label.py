"""Inventory headline counts that tell agents apart from scanned projects.

A bare repository scanned with ``agent-bom scan .`` is modelled as one
``project:<name>`` agent so the JSON, SARIF and graph surfaces keep a single
asset shape. The console must not call that repository "1 agents": here the
project count is split out so the headline reads as what was found.
"""

from __future__ import annotations

from agent_bom.models import AIBOMReport

_PROJECT_PREFIX = "project:"


def is_project_agent(agent) -> bool:
    return str(getattr(agent, "name", "") or "").startswith(_PROJECT_PREFIX)


def inventory_counts(report: AIBOMReport) -> tuple[int, int]:
    """Return ``(agents, projects)`` with the project pseudo-agents split out."""
    projects = sum(1 for agent in report.agents if is_project_agent(agent))
    return report.total_agents - projects, projects


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def inventory_subjects(report: AIBOMReport, *, bold: bool = True) -> str:
    """``"2 agents"``, ``"1 project"`` or ``"2 agents · 1 project"`` as Rich markup."""
    agents, projects = inventory_counts(report)
    parts: list[str] = []
    if agents or not projects:
        parts.append(_plural(agents, "agent"))
    if projects:
        parts.append(_plural(projects, "project"))
    if bold:
        parts = [f"[bold]{part}[/bold]" for part in parts]
    return " [dim]·[/dim] ".join(parts)


__all__ = ["inventory_counts", "inventory_subjects", "is_project_agent"]
