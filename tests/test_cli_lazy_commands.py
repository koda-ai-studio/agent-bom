"""Lazy command loading: help stays light and the command tree is unchanged."""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import click
from click.testing import CliRunner

from tests.cli_tree_snapshot import FIXTURE, snapshot

_HEAVY = [
    "agent_bom.inventory",
    "agent_bom.discovery",
    "agent_bom.parsers",
    "agent_bom.cli.agents.scan_cmd",
    "agent_bom.cli._server",
    "agent_bom.cli._runtime",
    "agent_bom.cli.cloud",
    "agent_bom.cli._skills_group",
    "httpx",
]


def _run(code: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code, *args],
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "AGENT_BOM_SKIP_UPDATE_CHECK": "1", "COLUMNS": "100"},
    )


def _loaded_after(*argv: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    result = _run(
        "import json, sys; sys.argv[0] = 'agent-bom'\n"
        "from agent_bom.__main__ import cli_main\n"
        "try:\n    cli_main()\nexcept SystemExit:\n    pass\n"
        "sys.stderr.write('\\nLOADED=' + json.dumps(sorted(m for m in sys.modules if m.startswith(('agent_bom', 'httpx')))))\n",
        *argv,
    )
    loaded = json.loads(result.stderr.rsplit("LOADED=", 1)[1])
    return result, loaded


def test_top_level_help_loads_no_command_module():
    result, loaded = _loaded_after("--help")

    assert result.returncode == 0, result.stderr
    assert "Usage:" in result.stdout
    assert [name for name in _HEAVY if name in loaded] == []
    assert len([name for name in loaded if name.startswith("agent_bom")]) <= 60, loaded


def test_subcommand_help_loads_only_that_command():
    result, loaded = _loaded_after("scan", "--help")

    assert result.returncode == 0, result.stderr
    assert "--offline" in result.stdout
    assert "agent_bom.cli.agents.scan_cmd" in loaded
    assert [name for name in ("agent_bom.cli._server", "agent_bom.cli._runtime", "agent_bom.cli.cloud") if name in loaded] == []


def test_full_command_tree_matches_the_recorded_tree():
    from agent_bom.cli import main

    recorded = json.loads(FIXTURE.read_text(encoding="utf-8"))
    current = snapshot(main)

    changed = sorted(path for path in recorded.keys() & current.keys() if recorded[path] != current[path])
    assert changed == []
    assert sorted(recorded.keys() - current.keys()) == []
    assert sorted(current.keys() - recorded.keys()) == []


def _isolated_subtree(name: str) -> dict[str, str]:
    result = _run(
        "import json, sys\n"
        "sys.path.insert(0, '.')\n"
        "from tests.cli_tree_snapshot import snapshot\n"
        "from agent_bom.cli import main\n"
        "import click\n"
        "ctx = click.Context(main, info_name='agent-bom')\n"
        f"print(json.dumps(snapshot(main.get_command(ctx, {name!r}), 'agent-bom {name}', ctx)))\n",
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_commands_sharing_objects_match_the_tree_when_loaded_alone():
    recorded = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for name in ("policy", "mcp", "runtime", "activity", "report", "guard", "registry", "connect", "up"):
        subtree = _isolated_subtree(name)
        expected = {
            path: digest for path, digest in recorded.items() if path == f"agent-bom {name}" or path.startswith(f"agent-bom {name} ")
        }
        assert subtree == expected, name


def test_static_help_index_matches_the_real_commands():
    from agent_bom.cli import main
    from agent_bom.cli._command_index import COMMAND_INDEX

    ctx = click.Context(main, info_name="agent-bom")
    assert sorted(COMMAND_INDEX) == sorted(main.list_commands(ctx))
    for name, entry in COMMAND_INDEX.items():
        command = main.get_command(ctx, name)
        assert command is not None, name
        assert entry.hidden == command.hidden, name
        assert entry.short_help == command.get_short_help_str(limit=48), name


def test_top_level_help_leads_with_the_new_user_commands():
    from agent_bom.cli import main

    output = CliRunner().invoke(main, ["--help"], terminal_width=100).output
    sections = re.findall(r"^([A-Z][A-Za-z ,&-]+):$", output, flags=re.MULTILINE)
    start = output.split("Get started:", 1)[1].split("Scanning:", 1)[0]
    first_commands = re.findall(r"^  ([a-z][a-z-]*)\s", start, flags=re.MULTILINE)
    setup = output.split("First run and setup:", 1)[1].split("Graph and attack paths:", 1)[0]

    assert sections[:4] == ["Options", "Get started", "Scanning", "First run and setup"]
    assert first_commands == ["connect", "scan", "graph", "report", "up"]
    assert re.findall(r"^  ([a-z][a-z-]*)\s", setup, flags=re.MULTILINE)[:2] == ["quickstart", "doctor"]
    assert "Other:" not in output


def test_every_visible_command_is_listed_once_in_top_level_help():
    from agent_bom.cli import main

    output = CliRunner().invoke(main, ["--help"], terminal_width=100).output
    commands_part = output.split("Get started:", 1)[1]
    listed = re.findall(r"^  ([a-z][a-z-]*)\s{2,}", commands_part, flags=re.MULTILINE)
    ctx = click.Context(main, info_name="agent-bom")
    visible = [name for name in main.list_commands(ctx) if not main.get_command(ctx, name).hidden]

    assert sorted(listed) == sorted(visible)
    assert len(listed) == len(set(listed))


def test_unknown_command_still_suggests_without_loading_commands():
    result, loaded = _loaded_after("scna")

    assert "Did you mean 'scan'?" in result.stderr
    assert "agent_bom.cli.agents.scan_cmd" not in loaded


def test_cli_package_reexports_resolve_lazily():
    result = _run(
        "import json, sys\n"
        "import agent_bom.cli as cli\n"
        "before = [m for m in ('agent_bom.inventory', 'agent_bom.discovery', 'agent_bom.cli.agents') if m in sys.modules]\n"
        "names = ['scan', '_parse_package_spec', '_make_console', '_NoOpDetector', 'discover_all']\n"
        "names += ['BANNER', 'SEVERITY_ORDER', 'sanitize_env_vars', '_build_agents_from_inventory']\n"
        "missing = [n for n in names if getattr(cli, n, None) is None]\n"
        "print(json.dumps([before, missing, callable(cli.cli_main)]))\n",
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [[], [], True]


def _statically_bound_names(source: str) -> set[str]:
    bound: set[str] = set()
    for node in ast.parse(source).body:
        body = node.body if isinstance(node, ast.If) else [node]
        for stmt in body:
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                bound.update(alias.asname or alias.name.split(".")[0] for alias in stmt.names)
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bound.add(stmt.name)
            elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                bound.update(t.id for t in targets if isinstance(t, ast.Name))
    return bound


def test_cli_package_all_names_are_statically_visible():
    from agent_bom import cli

    source = Path(cli.__file__).read_text(encoding="utf-8")
    assert sorted(set(cli.__all__) - _statically_bound_names(source)) == []
