"""The one-step path from a CLI install to the local dashboard.

The loopback dev API key is a credential: it is shown only on an interactive
terminal, never in a log record, a report file, or a printed command a user
might paste into shell history.
"""

from __future__ import annotations

import importlib.util
import shlex
import socket
import sys
import threading
import time
import webbrowser
from collections.abc import Sequence
from pathlib import Path

import click

from agent_bom import __version__

UI_MODULES = {"FastAPI": "fastapi", "Uvicorn": "uvicorn"}
# serve flags that are safe to echo back in a suggested command; credentials never are.
_ECHOED_SERVE_OPTIONS = ("host", "port", "persist")


def ui_extra_available() -> bool:
    return all(importlib.util.find_spec(module) is not None for module in UI_MODULES.values())


def missing_ui_modules() -> list[str]:
    return [label for label, module in UI_MODULES.items() if importlib.util.find_spec(module) is None]


def _released(version: str) -> bool:
    return all(part.isdigit() for part in version.split("."))


def one_step_launcher(*, version: str | None = None) -> str:
    """``agent-bom`` run through uvx with the UI extra, pinned to this release when it is one."""
    version = __version__ if version is None else version
    spec = f"agent-bom[ui]=={version}" if _released(version) else "agent-bom[ui]"
    return shlex.join(["uvx", "--from", spec, "agent-bom"])


def ui_launcher() -> str:
    """How to invoke a dashboard command from here: plain when the extra is installed, else the uvx one-step form."""
    return "agent-bom" if ui_extra_available() else one_step_launcher()


def one_step_ui_command(verb: str, args: Sequence[str] = (), *, version: str | None = None) -> str:
    """A command that runs ``agent-bom <verb>`` with the UI extra, without installing into this environment."""
    return " ".join([one_step_launcher(version=version), shlex.join([verb, *args])])


def serve_verb(ctx: click.Context) -> str:
    """``up`` forwards to ``serve`` through ``ctx.invoke``; repeat whichever verb the user typed."""
    return "up" if ctx.parent is not None and ctx.parent.command.name == "up" else "serve"


def echoed_serve_args(ctx: click.Context) -> list[str]:
    """The non-secret serve options the user typed, to repeat in a suggested command."""
    args: list[str] = []
    # `up` forwards to serve through ctx.invoke, so the typed values live on the parent context.
    contexts = [c for c in (ctx, ctx.parent) if c is not None]
    for name in _ECHOED_SERVE_OPTIONS:
        typed = next((c for c in contexts if c.get_parameter_source(name) == click.core.ParameterSource.COMMANDLINE), None)
        if typed is not None:
            args.extend([f"--{name}", str(typed.params[name])])
    return args


def fail_without_ui_extra(verb: str, args: Sequence[str] = ()) -> None:
    """Exit with the single command that starts the dashboard when the ``[ui]`` extra is missing."""
    missing = missing_ui_modules()
    if not missing:
        return
    click.echo(
        f"ERROR: {', '.join(missing)} required for `agent-bom {verb}` (the dashboard extra is not installed here).\n"
        "Start it in one step, without installing into this environment:\n"
        f"  {one_step_ui_command(verb, args)}\n"
        "Or install the extra here:  pip install 'agent-bom[ui]'  (or: uv pip install 'agent-bom[ui]')",
        err=True,
    )
    sys.exit(1)


def dashboard_bundled() -> bool:
    return (Path(__file__).resolve().parents[1] / "ui_dist" / "index.html").exists()


def interactive_terminal() -> bool:
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def dashboard_url(host: str, port: int, path: str = "/") -> str:
    shown = "127.0.0.1" if host in {"0.0.0.0", "::", ""} else host  # nosec B104 - display only
    if ":" in shown and not shown.startswith("["):
        shown = f"[{shown}]"
    return f"http://{shown}:{port}{path}"


def open_browser_when_ready(url: str, host: str, port: int, *, timeout: float = 60.0) -> threading.Thread:
    """Open ``url`` once the server accepts connections; gives up quietly after ``timeout``."""

    def _wait_and_open() -> None:
        target = "127.0.0.1" if host in {"0.0.0.0", "::", ""} else host  # nosec B104 - connect target only
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((target, port), timeout=1.0):
                    webbrowser.open(url)
                    return
            except OSError:
                time.sleep(0.25)

    thread = threading.Thread(target=_wait_and_open, name="agent-bom-open-browser", daemon=True)
    thread.start()
    return thread
