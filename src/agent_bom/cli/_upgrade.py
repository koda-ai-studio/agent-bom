"""``upgrade`` and the hidden ``update`` disambiguation command."""

from __future__ import annotations

import subprocess as sp
import sys

import click
from rich.console import Console

from agent_bom import __version__, http_client
from agent_bom.cli import _common


@click.command("upgrade")
@click.option("--check", "check_only", is_flag=True, help="Only check for updates, don't install.")
def upgrade_cmd(check_only: bool) -> None:
    """Check for and install the latest version of agent-bom.

    Guidance and the install action are install-method aware: only a pip install
    is upgraded automatically. pipx / uv tool / Homebrew / Docker / frozen-binary
    installs print the correct command for their own tool instead of running pip
    (which would break those installs).
    """

    def _ver_tuple(v: str) -> tuple[int, ...]:
        return tuple(int(x) for x in v.split(".") if x.isdigit())

    con = Console(stderr=True)
    con.print(f"  Current version: [bold]{__version__}[/bold]")

    method, upgrade_command = _common._detect_install_method()

    try:
        data = http_client.fetch_json("https://pypi.org/pypi/agent-bom/json", timeout=5)
        latest = data["info"]["version"]
    except Exception:
        con.print("  [red]Could not reach PyPI to check for updates.[/red]")
        con.print(f"  When back online, upgrade with: [cyan]{upgrade_command}[/cyan]")
        raise SystemExit(1)

    if _ver_tuple(latest) <= _ver_tuple(__version__):
        con.print(f"  Latest version:  [bold]{latest}[/bold]")
        con.print("  [green]You are up to date.[/green]")
        return

    con.print(f"  Latest version:  [bold yellow]{latest}[/bold yellow]")

    # Non-pip installs cannot be driven with `pip install --upgrade` — print the
    # right command for their tool and stop, whether or not --check was passed.
    if method != "pip":
        con.print(f"\n  Detected a [bold]{method}[/bold] install.")
        con.print(f"  Upgrade with: [cyan]{upgrade_command}[/cyan]")
        return

    if check_only:
        con.print(f"\n  Run: [cyan]{upgrade_command}[/cyan]")
        return

    con.print(f"\n  Upgrading agent-bom {__version__} → {latest}...")
    result = sp.run(
        [sys.executable, "-m", "pip", "install", "--upgrade", "agent-bom"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        con.print(f"  [green]Upgraded to agent-bom {latest}[/green]")
    else:
        con.print(f"  [red]Upgrade failed:[/red] {result.stderr.strip()[:200]}")
        con.print(f"  Try manually: [cyan]{upgrade_command}[/cyan]")
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# `update` disambiguation — a hidden command so `agent-bom update` gets a clear
# steer instead of a bare "Did you mean 'upgrade'?" (the verb is ambiguous:
# `agent-bom upgrade` upgrades the tool, `agent-bom db update` refreshes the
# vuln database). Exits 2 (usage), matching the CLI exit-code contract.
# ---------------------------------------------------------------------------


@click.command(
    "update",
    hidden=True,
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def update_cmd(ctx: click.Context, args: tuple[str, ...]) -> None:
    """Disambiguate the ambiguous `update` verb (hidden)."""
    click.echo(
        "`update` is not a command. Did you mean `agent-bom upgrade` "
        "(install a new version of the tool) or `agent-bom db update` "
        "(refresh the vulnerability database)?",
        err=True,
    )
    ctx.exit(2)
