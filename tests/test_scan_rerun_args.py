"""Follow-up commands repeat the scan the user ran, not a hardcoded ``scan .``."""

from __future__ import annotations

import click
import pytest

from agent_bom.cli.agents.scan_pipeline.rerun_args import typed_scan_arguments
from agent_bom.output.next_steps import graph_dashboard_command


def _typed(*args: str) -> str | None:
    from agent_bom.cli.agents.scan_cmd import scan

    captured: list[str | None] = []
    ctx = scan.make_context("scan", list(args))
    with ctx:
        captured.append(typed_scan_arguments())
    return captured[0]


def test_positional_path_and_flags_are_repeated_without_output_choices(tmp_path, monkeypatch):
    (tmp_path / "my proj").mkdir()
    monkeypatch.chdir(tmp_path)
    typed = _typed("my proj", "--offline", "-f", "json", "-o", "out.json", "--quiet")
    assert typed == "'my proj' --offline"


def test_secret_options_are_never_repeated():
    typed = _typed("--image", "registry.example/app:1", "--registry-user", "ci", "--registry-pass", "hunter2")
    assert "hunter2" not in typed
    assert "--image registry.example/app:1" in typed


def test_bare_scan_repeats_nothing():
    assert _typed() == ""


def test_outside_a_scan_command_there_is_nothing_to_repeat():
    assert typed_scan_arguments() is None
    with click.Context(click.Command("check")):
        assert typed_scan_arguments() is None


@pytest.mark.parametrize(
    ("target", "project"),
    [("'my proj' --offline", "'my proj'"), ("--project ./svc --offline", "./svc"), ("--image app:1", "."), ("", ".")],
)
def test_dashboard_command_names_the_scanned_project(target, project):
    command = graph_dashboard_command(target)
    assert f"quickstart --project {project} --run" in command
    assert command.endswith("--offline") == ("--offline" in target)
