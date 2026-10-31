"""Terminal line for ``check`` candidates the lookup could not decide."""

from __future__ import annotations

from typing import Any


def print_candidates(pkg: Any, console: Any, *, quiet: bool) -> None:
    """Name undecided local rows so a clean or incomplete verdict never hides them."""
    candidates = list(getattr(pkg, "possibly_affected", None) or [])
    if not candidates or quiet:
        return
    ids = ", ".join(str(entry["id"]) for entry in candidates[:5])
    suffix = f" (+{len(candidates) - 5} more)" if len(candidates) > 5 else ""
    if any(entry.get("reason") == "ambiguous_distro_release" for entry in candidates):
        console.print(
            f"  [yellow]⚠[/yellow] {len(candidates)} possibly affected candidate(s), not confirmed vulnerabilities: {ids}{suffix}. "
            "Scan the target image or filesystem with its OS metadata to resolve distro applicability."
        )
        return
    console.print(
        f"  [yellow]⚠[/yellow] {len(candidates)} possibly affected candidate(s) from local advisory rows without a range receipt "
        f"(no fix claimed, not counted): {ids}{suffix}. Run `agent-bom db update`, then re-check."
    )
