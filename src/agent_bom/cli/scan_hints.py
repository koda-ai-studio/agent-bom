"""Contextual next-step hints for the human scan summary.

Hints are static text: nothing is sent anywhere. They print only for a person
reading a terminal, never in machine-readable output, in CI, in quiet mode or
when ``AGENT_BOM_NO_HINTS`` is set. The one-time star line is remembered with a
marker file under the local state directory so it appears once per machine.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.markup import escape

from agent_bom.ci_detect import detect_ci_environment
from agent_bom.core.settings import env_flag
from agent_bom.output.next_steps import REPO_URL, next_step_items
from agent_bom.storage import state_home

HINTS_OPT_OUT_ENV = "AGENT_BOM_NO_HINTS"


def hints_opted_out() -> bool:
    return env_flag(HINTS_OPT_OUT_ENV)


def hints_enabled(con: Any, *, quiet: bool) -> bool:
    """True only for an interactive terminal outside CI, not quiet, not opted out."""
    if quiet or hints_opted_out() or detect_ci_environment().get("is_ci"):
        return False
    return bool(getattr(con, "is_terminal", False))


def next_step_hints(report: Any, *, target: str = ".", first_scan_of_target: bool = False) -> list[str]:
    """Rich-markup lines for the scan footer."""
    lines = []
    for item in next_step_items(report, target=target, first_scan_of_target=first_scan_of_target):
        url = f" · {item.url}" if item.url else ""
        lines.append(f"{item.label}: [bold]{escape(item.command)}[/bold]{url}")
    return lines


def _star_marker() -> Path:
    return state_home.state_path("hints", "star-shown")


def star_hint_once(*, scan_succeeded: bool) -> str | None:
    """Return the star line the first time a scan succeeds on this machine, else ``None``.

    The marker is written before the line is returned; when it cannot be
    written the line is withheld so a read-only home never repeats it.
    """
    if not scan_succeeded:
        return None
    marker = _star_marker()
    if marker.exists():
        return None
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch(exist_ok=False)
    except OSError:
        return None
    return f"If agent-bom helped, a GitHub star helps others find it: {REPO_URL} [dim](shown once · {HINTS_OPT_OUT_ENV}=1 hides tips)[/dim]"


def print_hints(con: Any, report: Any, *, target: str, first_scan_of_target: bool, scan_succeeded: bool) -> None:
    lines = next_step_hints(report, target=target, first_scan_of_target=first_scan_of_target)
    star = star_hint_once(scan_succeeded=scan_succeeded)
    if star:
        lines.append(star)
    for line in lines:
        con.print(f"  [cyan]→[/cyan] {line}")


__all__ = ["HINTS_OPT_OUT_ENV", "hints_enabled", "hints_opted_out", "next_step_hints", "print_hints", "star_hint_once"]
