"""CI templates parse and only use agent-bom flags the CLI accepts."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import click
import pytest
import yaml

from agent_bom.cli import main

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = sorted((ROOT / "examples" / "ci").glob("*.yml"))
REUSABLE = ROOT / ".github" / "workflows" / "agent-bom-reusable.yml"


def _commands(node: object) -> list[str]:
    if isinstance(node, dict):
        return [command for value in node.values() for command in _commands(value)]
    if isinstance(node, list):
        return [command for value in node for command in _commands(value)]
    if isinstance(node, str):
        lines = [line.strip() for line in node.splitlines()]
        return [line for line in lines if line.startswith("agent-bom ") and len(shlex.split(line)) > 2]
    return []


def test_every_ci_system_has_a_template() -> None:
    assert {path.name for path in TEMPLATES} == {"gitlab-ci.yml", "azure-pipelines.yml", "bitbucket-pipelines.yml"}


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda path: path.name)
def test_template_commands_are_valid_cli_invocations(path: Path) -> None:
    commands = _commands(yaml.safe_load(path.read_text(encoding="utf-8")))
    assert commands, path.name
    for command in commands:
        argv = shlex.split(command)[1:]
        ctx = click.Context(main)
        sub = main.get_command(ctx, argv[0])
        assert sub is not None, command
        accepted = {opt for param in sub.params for opt in getattr(param, "opts", [])}
        options = {arg for arg in argv if arg.startswith("-")}
        assert options <= accepted, command
        assert "--fail-on-severity" in options or "cyclonedx" in argv, command


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda path: path.name)
def test_template_pins_the_published_release(path: Path) -> None:
    assert re.search(r"pip install --quiet agent-bom==\d+\.\d+\.\d+", path.read_text(encoding="utf-8"))


def test_reusable_workflow_forwards_only_real_action_inputs() -> None:
    workflow = yaml.safe_load(REUSABLE.read_text(encoding="utf-8"))
    action_inputs = set(yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))["inputs"])
    on = workflow.get("on") or workflow.get(True)
    call_inputs = set(on["workflow_call"]["inputs"])
    step = next(step for step in workflow["jobs"]["scan"]["steps"] if "agent-bom@" in str(step.get("uses", "")))
    assert set(step["with"]) <= action_inputs
    assert set(step["with"]) == call_inputs
    assert workflow["permissions"] == {"contents": "read"}
