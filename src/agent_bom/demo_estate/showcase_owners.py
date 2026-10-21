"""Fictional remediation teams for the hand-built showcase agents.

Team names, not addresses: the API masks every email-shaped owner, so an
address would render as ``a***@e***.invalid`` instead of a team a viewer can
recognise. These are demo routing policy, never a real person or domain.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

SHOWCASE_AGENT_OWNERS: dict[str, str] = {
    "cursor": "Developer Platform team",
    "langchain-service": "AI Platform team",
    "support-copilot": "Support Engineering team",
    "data-pipeline": "Data Platform team",
    "claude-desktop": "Workplace IT team",
}


def assign_showcase_owners(findings: Iterable[Any], *, agent_of: Callable[[Any], str | None]) -> None:
    """Route each unowned showcase finding to its agent's team; explicit owners stay."""
    for finding in findings:
        if getattr(finding, "owner", None):
            continue
        team = SHOWCASE_AGENT_OWNERS.get(agent_of(finding) or "")
        if team:
            finding.owner = team
