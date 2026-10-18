"""Console style rendering helpers."""

from __future__ import annotations

from rich.console import Console

from agent_bom.core.severity import severity_basis
from agent_bom.core.terminal import safe_emoji as safe_emoji
from agent_bom.models import Severity
from agent_bom.output.finding_views import (
    finding_severity,
)

SEVERITY_TEXT: dict[Severity, str] = {
    Severity.CRITICAL: "red bold",
    Severity.HIGH: "#e67e22 bold",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
}


SEVERITY_BADGES: dict[Severity, str] = {
    Severity.CRITICAL: "white on red",
    Severity.HIGH: "white on #e67e22",
    Severity.MEDIUM: "black on yellow",
    Severity.LOW: "white on #555555",
    Severity.UNKNOWN: "black on white",
}


console = Console()


def _sev_badge(severity: Severity) -> str:
    """Render a severity badge with background color: ` CRIT `, ` HIGH `, etc."""
    style = SEVERITY_BADGES.get(severity, "white")
    labels = {
        Severity.CRITICAL: " CRIT ",
        Severity.HIGH: " HIGH ",
        Severity.MEDIUM: " MED  ",
        Severity.LOW: " LOW  ",
        Severity.UNKNOWN: " ADV  ",
    }
    label = labels.get(severity, f" {severity.value.upper()} ")
    return f"[{style}]{label}[/{style}]"


def _finding_sev_badge(finding) -> str:
    unscored = severity_basis((getattr(finding, "evidence", None) or {}).get("severity_source")) == "default"
    return _sev_badge(finding_severity(finding)) + (" [dim](unscored)[/dim]" if unscored else "")


def _console() -> Console:
    """Honor the legacy renderer resolver, including caller-installed capture hooks."""
    from agent_bom.output import console_render

    return console_render._console()
