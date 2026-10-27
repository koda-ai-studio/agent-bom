"""Explicit flags on focused commands (`image`, `fs`, `sbom`, ...) beat profile defaults.

Focused commands forward to `scan` with ``ctx.invoke``; Click records no
parameter source for forwarded values, so the profile could not tell an explicit
``--format console`` from the default and rewrote it to the profile's ``json``.
"""

from __future__ import annotations

from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli._param_source import invoke_forwarding, is_explicit
from agent_bom.cli._profiles import apply_scan_profile_defaults
from agent_bom.cli.agents.scan_pipeline import prepare

_JSON_PROFILE = """
current_profile = "prod"

[profiles.prod]
format = "json"
output = "agent-bom-report.json"
preset = "enterprise"
"""


@pytest.fixture
def json_profile(monkeypatch, tmp_path: Path) -> Path:
    config_path = tmp_path / "config.toml"
    config_path.write_text(_JSON_PROFILE, encoding="utf-8")
    monkeypatch.setenv("AGENT_BOM_CONFIG", str(config_path))
    monkeypatch.delenv("AGENT_BOM_PROFILE", raising=False)
    return config_path


def _forwarding_pair(seen: dict):
    @click.command()
    @click.option("--output")
    @click.option("--format", "output_format", default="console")
    @click.option("--preset")
    def _scan(output: str | None, output_format: str, preset: str | None) -> None:
        seen["values"] = apply_scan_profile_defaults(
            output=output,
            output_format=output_format,
            preset=preset,
            nvd_api_key=None,
            push_url=None,
            push_api_key=None,
            clickhouse_url=None,
        )[:3]
        seen["explicit_format"] = is_explicit(click.get_current_context(), "output_format")

    @click.command()
    @click.option("-o", "--output", "output_path")
    @click.option("-f", "--format", "output_format", default="console")
    @click.pass_context
    def _focused(ctx, output_path: str | None, output_format: str) -> None:
        invoke_forwarding(ctx, _scan, aliases={"output": "output_path"}, output=output_path, output_format=output_format)

    return _focused


@pytest.mark.usefixtures("json_profile")
def test_explicit_console_format_beats_profile_json():
    seen: dict = {}
    result = CliRunner().invoke(_forwarding_pair(seen), ["--format", "console"])
    assert result.exit_code == 0, result.output
    assert seen["values"][1] == "console"
    assert seen["explicit_format"] is True


@pytest.mark.usefixtures("json_profile")
def test_explicit_output_beats_profile_output_through_alias():
    seen: dict = {}
    result = CliRunner().invoke(_forwarding_pair(seen), ["-o", "mine.json", "-f", "json"])
    assert result.exit_code == 0, result.output
    assert seen["values"][:2] == ("mine.json", "json")


@pytest.mark.usefixtures("json_profile")
def test_unset_flags_still_take_profile_defaults():
    seen: dict = {}
    result = CliRunner().invoke(_forwarding_pair(seen), [])
    assert result.exit_code == 0, result.output
    assert seen["values"] == ("agent-bom-report.json", "json", "enterprise")
    assert seen["explicit_format"] is False


def test_forwarded_sources_do_not_leak_to_later_invocations(json_profile):
    seen: dict = {}
    command = _forwarding_pair(seen)
    runner = CliRunner()
    assert runner.invoke(command, ["--format", "console"]).exit_code == 0
    assert runner.invoke(command, []).exit_code == 0
    assert seen["values"][1] == "json"


def _capture_resolved_options(monkeypatch) -> dict:
    captured: dict = {}

    def _stop(opts, st):
        captured.update(output_format=opts.output_format, output=opts.output)
        raise click.exceptions.Exit(0)

    monkeypatch.setattr(prepare, "_apply_project_config", _stop)
    return captured


@pytest.mark.parametrize(
    ("argv", "expected_format", "expected_output"),
    [
        (["--format", "console"], "console", None),
        (["-f", "sarif", "-o", "out.sarif"], "sarif", "out.sarif"),
        ([], "json", "agent-bom-report.json"),
    ],
)
def test_image_command_flags_beat_profile(json_profile, monkeypatch, tmp_path, argv, expected_format, expected_output):
    image_tar = tmp_path / "image.tar"
    image_tar.write_bytes(b"")
    captured = _capture_resolved_options(monkeypatch)
    result = CliRunner().invoke(main, ["image", "--tar", str(image_tar), *argv])
    assert result.exit_code == 0, result.output
    assert captured == {"output_format": expected_format, "output": expected_output}


@pytest.mark.parametrize("command", ["fs", "sbom"])
def test_other_focused_commands_honor_explicit_console(json_profile, monkeypatch, tmp_path, command):
    target = tmp_path / ("bom.json" if command == "sbom" else "root")
    if command == "sbom":
        target.write_text('{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}', encoding="utf-8")
    else:
        target.mkdir()
    captured = _capture_resolved_options(monkeypatch)
    result = CliRunner().invoke(main, [command, str(target), "--format", "console"])
    assert result.exit_code == 0, result.output
    assert captured["output_format"] == "console"


def test_no_command_forwards_options_to_scan_with_bare_ctx_invoke():
    """Forwarding with keyword options must go through ``invoke_forwarding`` so sources survive."""
    import ast

    cli_root = Path(__file__).resolve().parents[1] / "src" / "agent_bom" / "cli"
    offenders = []
    for path in sorted(cli_root.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "invoke"
                and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "scan"
                and node.keywords
            ):
                offenders.append(f"{path.relative_to(cli_root)}:{node.lineno}")
    assert offenders == []
