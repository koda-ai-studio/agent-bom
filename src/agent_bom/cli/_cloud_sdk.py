"""Stop a cloud scan before any discovery when the provider's SDK is not installed."""

from __future__ import annotations

import importlib.util

from rich.console import Console
from rich.markup import escape

# Any one module is enough: each provider's discovery imports from the same set.
PROVIDER_SDKS = {
    "aws": ("boto3",),
    "azure": ("azure.identity",),
    "gcp": ("google.cloud.aiplatform", "google.cloud.functions_v2", "google.cloud.container_v1", "google.cloud.run_v2"),
}


def _installed(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def providers_missing_sdk(providers: list[str]) -> list[str]:
    return [p for p in providers if p in PROVIDER_SDKS and not any(_installed(module) for module in PROVIDER_SDKS[p])]


def exit_if_sdk_missing(providers: list[str]) -> list[str]:
    """``providers`` when every SDK is installed; otherwise exit 1 with the one install command, before any scan."""
    missing = providers_missing_sdk(providers)
    if not missing:
        return providers
    con = Console(stderr=True)
    install = escape(f"pip install 'agent-bom[{','.join(missing)}]'")
    con.print(f"[red]Cloud scan needs the {', '.join(p.upper() for p in missing)} SDK, which is not installed.[/red]")
    con.print(f"  Install it and retry: [cyan]{install}[/cyan]")
    con.print("  [dim]Nothing was scanned (exit 1: missing optional dependency).[/dim]")
    raise SystemExit(1)
