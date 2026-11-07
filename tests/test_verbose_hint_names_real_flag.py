"""Every "rerun for more detail" hint names a flag the running command accepts."""

from __future__ import annotations

import ast
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from agent_bom.cli._entry import make_entry_point
from agent_bom.verbose_hint import DEBUG_ENV_HINT, verbose_hint

SRC = Path(__file__).resolve().parents[1] / "src" / "agent_bom"

SCAN_FORWARDING_COMMANDS = [
    ("image",),
    ("fs",),
    ("iac",),
    ("sbom",),
    ("cloud", "snowflake"),
    ("cloud", "databricks"),
    ("cloud", "huggingface"),
    ("cloud", "ollama"),
    ("cloud", "posture"),
]


def _resolve(path: tuple[str, ...]) -> click.Command:
    from agent_bom.cli import main

    cmd: click.Command = main
    for name in path:
        assert isinstance(cmd, click.Group)
        found = cmd.get_command(click.Context(cmd), name)
        assert found is not None, name
        cmd = found
    return cmd


@pytest.mark.parametrize("path", SCAN_FORWARDING_COMMANDS, ids=lambda p: " ".join(p))
def test_scan_forwarding_commands_accept_verbose(path) -> None:
    opts = {opt for param in _resolve(path).params for opt in getattr(param, "opts", [])}
    assert {"--verbose", "-v"} <= opts


def test_image_forwards_verbose_into_scan(monkeypatch) -> None:
    from agent_bom.cli import _focused_commands

    seen: dict = {}
    monkeypatch.setattr(_focused_commands, "invoke_forwarding", lambda ctx, cmd, **kw: seen.update(kw))
    result = CliRunner().invoke(_focused_commands.image_cmd, ["nginx:1.25", "--verbose"])
    assert result.exit_code == 0, result.output
    assert seen["verbose"] is True


def test_hint_names_verbose_when_the_typed_command_has_it() -> None:
    captured: list[str] = []

    @click.group()
    def root() -> None:
        pass

    @root.command("scanlike")
    @click.option("--verbose", "-v", is_flag=True)
    def scanlike(verbose: bool) -> None:
        captured.append(verbose_hint())

    @root.command("plain")
    def plain() -> None:
        captured.append(verbose_hint())

    @root.group("grp", invoke_without_command=True)
    @click.pass_context
    def grp(ctx: click.Context) -> None:
        if ctx.invoked_subcommand is None:
            ctx.invoke(scanlike)

    runner = CliRunner()
    assert runner.invoke(root, ["scanlike"]).exit_code == 0
    assert runner.invoke(root, ["plain"]).exit_code == 0
    assert runner.invoke(root, ["grp"]).exit_code == 0
    assert captured == ["--verbose", DEBUG_ENV_HINT, DEBUG_ENV_HINT]


def test_hint_outside_a_command_names_the_env_var() -> None:
    assert verbose_hint() == DEBUG_ENV_HINT


@click.group()
def _group() -> None:
    pass


@_group.command("noverbose")
def _noverbose() -> None:
    raise RuntimeError("boom")


@_group.command("withverbose")
@click.option("--verbose", "-v", is_flag=True)
def _withverbose(verbose: bool) -> None:
    raise RuntimeError("boom")


def _run_entry(monkeypatch, capsys, argv: list[str]) -> str:
    monkeypatch.setattr("sys.argv", ["agent-bom", *argv])
    monkeypatch.setattr("agent_bom.cli._entry._check_for_update_bg", lambda: None)
    with pytest.raises(SystemExit):
        make_entry_point(_group)()
    return capsys.readouterr().err


def test_entry_traceback_hint_matches_the_command(monkeypatch, capsys) -> None:
    monkeypatch.delenv("AGENT_BOM_LOG_LEVEL", raising=False)
    assert "--verbose" not in _run_entry(monkeypatch, capsys, ["noverbose"])
    assert "AGENT_BOM_LOG_LEVEL=DEBUG" in _run_entry(monkeypatch, capsys, ["noverbose"])
    assert "Run with --verbose" in _run_entry(monkeypatch, capsys, ["withverbose"])


def test_entry_prints_traceback_with_debug_env(monkeypatch, capsys) -> None:
    monkeypatch.setenv("AGENT_BOM_LOG_LEVEL", "DEBUG")
    err = _run_entry(monkeypatch, capsys, ["noverbose"])
    assert "Traceback" in err
    assert "for the full traceback" not in err


def test_no_hardcoded_verbose_hint_strings_left() -> None:
    offenders: list[str] = []
    for path in SRC.rglob("*.py"):
        # _entry.py prints its --verbose hint only after checking the typed command has it.
        if path.name == "verbose_hint.py" or path.relative_to(SRC).as_posix() == "cli/_entry.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value.lower()
                if "--verbose" in text and any(word in text for word in ("use ", "run with", "rerun", "for details")):
                    offenders.append(f"{path.relative_to(SRC)}:{node.lineno}: {node.value!r}")
    assert not offenders, "\n".join(offenders)
