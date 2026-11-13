"""CLI entry point for agent-bom.

This package splits the CLI into focused modules while preserving the
public API: ``main`` (click group), ``cli_main`` (entry point), and
backward-compatible imports used by tests.

Subcommands load lazily: ``main.commands`` imports a command's module the
first time it is looked up (see ``_lazy_commands``), so ``--help`` and any
single command skip the rest of the CLI. Re-exported helpers resolve on
first attribute access for the same reason.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

import click

from agent_bom import __version__
from agent_bom.__main__ import version_message
from agent_bom.cli._agent_mode import AGENT_MODE_ENV_VAR
from agent_bom.cli._command_index import COMMAND_INDEX
from agent_bom.cli._entry import make_entry_point
from agent_bom.cli._grouped_help import GroupedGroup
from agent_bom.cli._lazy_commands import LazyCommands
from agent_bom.output.brand_tokens import CLI_MAIN_HELP

if TYPE_CHECKING:
    # Static view of the lazy names in ``__all__``; at runtime ``__getattr__`` imports them on first access.
    from agent_bom.cli._check import _parse_package_spec as _parse_package_spec
    from agent_bom.cli._common import _make_console as _make_console
    from agent_bom.cli._runtime import _NoOpDetector as _NoOpDetector
    from agent_bom.cli.agents.scan_cmd import scan as scan
    from agent_bom.discovery import discover_all as discover_all

# Names other modules and tests import from ``agent_bom.cli``; each resolves on
# first access. ``discover_all`` stays here so patch("agent_bom.cli.discover_all")
# keeps working, although new code should import it from agent_bom.discovery.
_LAZY_REEXPORTS: dict[str, tuple[str, str]] = {
    "BANNER": ("agent_bom.cli._common", "BANNER"),
    "SEVERITY_ORDER": ("agent_bom.cli._common", "SEVERITY_ORDER"),
    "_build_agents_from_inventory": ("agent_bom.inventory", "build_agents_from_inventory"),
    "_check_for_update_bg": ("agent_bom.cli._common", "_check_for_update_bg"),
    "_check_optional_dep": ("agent_bom.cli._common", "_check_optional_dep"),
    "_make_console": ("agent_bom.cli._common", "_make_console"),
    "_print_update_notice": ("agent_bom.cli._common", "_print_update_notice"),
    "_update_check_done": ("agent_bom.cli._common", "_update_check_done"),
    "_update_check_result": ("agent_bom.cli._common", "_update_check_result"),
    "logger": ("agent_bom.cli._common", "logger"),
    "sanitize_env_vars": ("agent_bom.security", "sanitize_env_vars"),
    "discover_all": ("agent_bom.discovery", "discover_all"),
    "_parse_package_spec": ("agent_bom.cli._check", "_parse_package_spec"),
    "_NoOpDetector": ("agent_bom.cli._runtime", "_NoOpDetector"),
    "scan": ("agent_bom.cli.agents.scan_cmd", "scan"),
    "upgrade_cmd": ("agent_bom.cli._upgrade", "upgrade_cmd"),
    "update_cmd": ("agent_bom.cli._upgrade", "update_cmd"),
}


def __getattr__(name: str) -> Any:
    target = _LAZY_REEXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr = target
    return getattr(importlib.import_module(module_name), attr)


def _print_startup_banner() -> None:
    """Render the ``agent-bom`` no-args startup banner.

    Uses the locked product mark (BOM with agent O) plus wordmark/tagline so
    CLI and dashboard share one brand. Compact (≤ 14 lines) for standard terminals.
    """
    from rich.console import Console

    from agent_bom.output.brand_tokens import print_cli_startup_banner

    print_cli_startup_banner(Console(), version=__version__)


@click.group(
    cls=GroupedGroup,
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=True,
    help=CLI_MAIN_HELP,
)
@click.option(
    "--profile",
    envvar="AGENT_BOM_PROFILE",
    metavar="NAME",
    help="Use a named CLI profile from ~/.agent-bom/config.toml.",
)
@click.option(
    "--agent-mode",
    is_flag=True,
    envvar=AGENT_MODE_ENV_VAR,
    help="Emit stable machine-readable JSON for assistant and automation callers.",
)
@click.version_option(
    version=__version__,
    prog_name="agent-bom",
    message=version_message(),
)
@click.pass_context
def main(ctx: click.Context, profile: str | None, agent_mode: bool):
    if profile:
        import os as _os

        from agent_bom.cli._profiles import load_active_profile

        try:
            load_active_profile(profile)
        except click.ClickException as exc:
            raise click.BadParameter(str(exc), param_hint="'--profile'") from exc

        _os.environ["AGENT_BOM_PROFILE"] = profile
    if agent_mode:
        import os as _os

        previous_agent_mode = _os.environ.get(AGENT_MODE_ENV_VAR)
        _os.environ[AGENT_MODE_ENV_VAR] = "1"

        def _restore_agent_mode_env() -> None:
            if previous_agent_mode is None:
                _os.environ.pop(AGENT_MODE_ENV_VAR, None)
            else:
                _os.environ[AGENT_MODE_ENV_VAR] = previous_agent_mode

        ctx.call_on_close(_restore_agent_mode_env)
    if ctx.invoked_subcommand is None:
        _print_startup_banner()


main.commands = LazyCommands(COMMAND_INDEX)

# The lambda resolves the module global at call time so unittest.mock.patch("agent_bom.cli.main") works
cli_main = make_entry_point(lambda: main, "agent-bom")


__all__ = [
    "main",
    "cli_main",
    "scan",
    "_parse_package_spec",
    "_make_console",
    "_NoOpDetector",
    "discover_all",
]

if __name__ == "__main__":
    cli_main()  # pragma: no cover
