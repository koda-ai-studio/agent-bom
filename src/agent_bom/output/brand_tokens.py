"""Shared product brand tokens for terminal + lane labels.

Product name is always ``agent-bom``. The mark is BOM with an agent HUD in the O.
See ``docs/VISUAL_LANGUAGE.md``.
"""

from __future__ import annotations

from dataclasses import dataclass

PRODUCT_NAME = "agent-bom"
# Canonical tagline (pyproject ``description`` without the trailing period). One
# constant feeds ``--version``, ``--help``, the CLI banner and OpenAPI / HTML chrome;
# ``scripts/check_release_consistency.py`` asserts the non-Python surfaces match.
POSITIONING_META = "AI supply-chain BOM: every agent, MCP server and AI package, and what each one can reach"
POSITIONING_SHORT = POSITIONING_META
TAGLINE_CHAIN = "agent → MCP server → packages → CVEs → blast radius"
DOCS_URL = "https://github.com/koda-ai-studio/agent-bom"
REPORT_TITLE = f"{PRODUCT_NAME} scan report"

# ``agent-bom --help`` text; the first line is the canonical tagline. Kept here, off the
# scan path, because it carries the docs URL (see tests/test_plugin_egress_hosts.py).
CLI_MAIN_HELP = f"""agent-bom — {POSITIONING_SHORT}.

\b
Maps the full trust chain: agent → MCP server → packages → CVEs → blast radius.

\b
Quick start:
  agent-bom quickstart                          print local scan, sample-data, and API/UI next steps
  agent-bom scan                                 discover + scan local agents and MCP servers
  agent-bom scan -p .                            scan project manifests plus agent/MCP context
  agent-bom samples first-run                    write an inspectable sample AI stack
  agent-bom where                                show MCP discovery paths checked on this machine
  agent-bom mesh                                 show the live machine-wide agent/MCP topology
  agent-bom mesh --project .                     show project-local topology only
  agent-bom skills scan .                        scan skills and instruction files
  agent-bom skills rescan                        revisit previously cataloged skills
  agent-bom check flask@2.0.0 --ecosystem pypi  pre-install CVE gate
  agent-bom image nginx:latest                   container image scan
  agent-bom iac Dockerfile k8s/ infra/main.tf    IaC scan across one or more paths
  agent-bom proxy "npx @mcp/server-fs /workspace"  MCP security proxy

\b
Tip: `agent-bom -h` groups commands by scanning, runtime, MCP, reporting, and governance.

\b
Docs:  https://koda-ai-studio.github.io/agent-bom/
"""

# Minimal dark mark for API /docs favicon when package data is unavailable.
MARK_SVG_DARK = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"
  role="img" aria-label="agent-bom mark — BOM with an agent face in the O">
  <defs>
    <linearGradient id="abm" x1="8" y1="6" x2="56" y2="58" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#34d399"/>
      <stop offset="100%" stop-color="#06b6d4"/>
    </linearGradient>
  </defs>
  <rect x="3.5" y="3.5" width="57" height="57" rx="15" fill="#0c1210" stroke="url(#abm)" stroke-width="2"/>
  <g transform="translate(0 3)">
  <!-- B -->
  <path fill="url(#abm)"
    d="M7.5 16.5h7.4c3.7 0 5.9 1.9 5.9 4.7 0 1.9-1.05 3.25-2.75 3.95 2 .8 3.3 2.35 3.3 4.7 0 3.05-2.45 4.95-6.45 4.95H7.5
    V16.5zm3.65 3.1v4.7h2.8c1.7 0 2.7-.85 2.7-2.35s-1.1-2.35-2.95-2.35H11.15
    zm0 7.55v5h3.15c1.85 0 3-.95 3-2.55s-1.1-2.45-3.05-2.45H11.15z"/>
  <!-- O as the agent face: ring-as-head + antenna + two eyes + mouth (readable at small sizes) -->
  <circle cx="32" cy="30.2" r="12" fill="#0f1a17" stroke="url(#abm)" stroke-width="2.4"/>
  <path d="M32 18.4V13.5" stroke="url(#abm)" stroke-width="2.2" stroke-linecap="round"/>
  <circle cx="32" cy="11.9" r="2.1" fill="url(#abm)"/>
  <circle cx="28" cy="28.9" r="2.7" fill="#34d399"/>
  <circle cx="36" cy="28.9" r="2.7" fill="#22d3ee"/>
  <path d="M27.5 34.5Q32 39 36.5 34.5" fill="none" stroke="url(#abm)" stroke-width="1.9" stroke-linecap="round"/>
  <!-- M -->
  <path fill="url(#abm)" d="M44.5 16.5h3.7l3.75 11.7 3.75-11.7H59.5v19.6h-3.3V27.8l-3.65 8.5h-2.95l-3.5-8.5v8.5h-3.3V16.5h1.7z"/>
  </g>

</svg>
"""

# Terminal mark: BOM with agent HUD in the O (visor + antenna cue).
_MARK_UNICODE = (
    "  ┌───────────┐",
    "  │ B [=o=] M │",
    "  └───────────┘",
)
_MARK_ASCII = (
    "  +-----------+",
    "  | B [=o=] M |",
    "  +-----------+",
)


@dataclass(frozen=True)
class LaneToken:
    """Terminal-safe label + Rich style for a product lane."""

    label: str
    style: str


LANE_TOKENS: dict[str, LaneToken] = {
    "discover": LaneToken(label="DISCOVER", style="blue"),
    "scan": LaneToken(label="SCAN", style="red"),
    "analyze": LaneToken(label="ANALYZE", style="yellow"),
    "protect": LaneToken(label="PROTECT", style="magenta"),
    "govern": LaneToken(label="GOVERN", style="green"),
}


def lane_token(name: str) -> LaneToken:
    """Return a lane token, defaulting to a neutral uppercase label."""

    key = name.strip().lower()
    return LANE_TOKENS.get(key, LaneToken(label=key.upper() or "AGENT-BOM", style="cyan"))


def lane_title(name: str, title: str) -> str:
    """Render a compact lane-prefixed section title."""

    token = lane_token(name)
    return f"[{token.style}]{token.label}[/{token.style}] [dim]|[/dim] [bold]{title}[/bold]"


def _stdout_supports(text: str) -> bool:
    import sys

    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        text.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def cli_mark_lines(*, force_ascii: bool = False) -> tuple[str, ...]:
    """Return the BOM-with-agent-O mark as terminal lines."""

    if force_ascii or not _stdout_supports("\n".join(_MARK_UNICODE)):
        return _MARK_ASCII
    return _MARK_UNICODE


def cli_banner_plain(*, version: str | None = None, force_ascii: bool = False) -> str:
    """Plain-text lockup for ``BANNER`` / non-Rich callers."""

    lines = list(cli_mark_lines(force_ascii=force_ascii))
    ver = f"  v{version}" if version else ""
    lines.append(f"  {PRODUCT_NAME}{ver}")
    lines.append(f"  {POSITIONING_SHORT}")
    return "\n" + "\n".join(lines) + "\n"


def print_cli_startup_banner(console: object, *, version: str) -> None:
    """Render the no-args CLI splash with mark, wordmark, and quick start."""

    mark = cli_mark_lines()
    # ``console`` is a Rich Console; typed as object to avoid a hard import cycle.
    print_ = getattr(console, "print")
    print_()
    for line in mark:
        print_(f"[bold cyan]{line}[/bold cyan]")
    print_()
    print_(f"    [bold]{PRODUCT_NAME}[/bold] [dim]·[/dim] [dim]v{version}[/dim]")
    print_(f"    [dim]{POSITIONING_SHORT}[/dim]")
    print_()
    print_(f"    [dim]{TAGLINE_CHAIN}[/dim]")
    print_()
    print_("    [bold]Quick start[/bold]")
    print_(f"    [cyan]▶[/cyan] [bold]{PRODUCT_NAME} scan[/bold]                 discover + scan local agents and MCP servers")
    print_(f"    [cyan]▶[/cyan] [bold]{PRODUCT_NAME} samples first-run[/bold]   write an inspectable sample AI stack")
    print_(f"    [cyan]▶[/cyan] [bold]{PRODUCT_NAME} -h[/bold]                  full command catalog (grouped)")
    print_()
    print_(f"    [dim]Docs:[/dim]  [link={DOCS_URL}]{DOCS_URL}[/link]")
    print_()


def emit_cli_runtime_summary(
    title: str,
    rows: list[tuple[str, str]],
    *,
    err: bool = False,
    force_ascii: bool = False,
) -> None:
    """Print the BOM mark + product title + aligned key/value rows for serve/gateway."""

    import click

    click.echo("", err=err)
    for line in cli_mark_lines(force_ascii=force_ascii):
        click.echo(line, err=err)
    click.echo(f"  {title}", err=err)
    for label, value in rows:
        click.echo(f"  {label:<11} {value}", err=err)
    click.echo("  Press Ctrl+C to stop.\n", err=err)


__all__ = [
    "DOCS_URL",
    "LANE_TOKENS",
    "MARK_SVG_DARK",
    "CLI_MAIN_HELP",
    "POSITIONING_META",
    "POSITIONING_SHORT",
    "PRODUCT_NAME",
    "REPORT_TITLE",
    "TAGLINE_CHAIN",
    "LaneToken",
    "cli_banner_plain",
    "cli_mark_lines",
    "emit_cli_runtime_summary",
    "lane_title",
    "lane_token",
    "print_cli_startup_banner",
]
