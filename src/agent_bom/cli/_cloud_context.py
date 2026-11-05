"""Selected cloud context and operator-facing collection status."""

from __future__ import annotations

import shutil
import subprocess
import uuid
from collections.abc import Callable, Mapping

from rich.console import Console

from agent_bom.cloud.gcp_inv import _base as gcp_base


def active_cloud_target(provider: str) -> str | None:
    """Resolve the selected CLI/ADC scope without changing accounts or logging SDK output."""
    if provider == "gcp":
        project, _note = gcp_base._derive_default_project()
        if project:
            return project
        command = ["gcloud", "config", "get-value", "project", "--quiet"]
    elif provider == "azure":
        command = ["az", "account", "show", "--query", "id", "--output", "tsv"]
    else:
        return None
    executable = shutil.which(command[0])
    if not executable:
        return None
    try:
        result = subprocess.run(
            [executable, *command[1:]], capture_output=True, encoding="utf-8", timeout=5, stdin=subprocess.DEVNULL, check=False
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return None
    value = result.stdout.strip()
    if result.returncode or not value or value in {"(unset)", "None", "null"} or len(value) > 255 or any(c.isspace() for c in value):
        return None
    if provider == "azure":
        try:
            return str(uuid.UUID(value))
        except ValueError:
            return None
    return value if all(c.isascii() and (c.isalnum() or c in "._:-") for c in value) else None


def print_provider_status(
    providers: list[str],
    skipped: list[str],
    hints: Mapping[str, str],
    status: Callable[[str], tuple[bool, str]],
    verification: Callable[[str], tuple[bool, str]],
    *,
    verify: bool,
) -> None:
    """Display the selected providers and credential sources, without reading tokens."""
    con = Console(stderr=True)
    for provider in providers:
        _has, source = status(provider)
        line = f"  [green]{provider}[/green]: scanning [dim](creds via {source})[/dim]"
        if verify:
            ok, detail = verification(provider)
            mark = "[green]verified[/green]" if ok else "[yellow]unverified[/yellow]"
            line += f" · {mark} [dim]({detail})[/dim]"
        con.print(line)
    for provider in skipped:
        con.print(f"  [yellow]{provider}[/yellow]: skipped — no credentials [dim](set up: {hints[provider]})[/dim]")
