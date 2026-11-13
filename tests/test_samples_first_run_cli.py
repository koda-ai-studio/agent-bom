"""``agent-bom samples first-run`` takes its output directory as a positional argument or ``-o``."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from agent_bom.cli import main


def test_positional_output_directory(tmp_path: Path) -> None:
    target = tmp_path / "sample1"
    result = CliRunner().invoke(main, ["samples", "first-run", str(target)])
    assert result.exit_code == 0, result.output
    assert (target / "inventory.json").is_file()
    assert f"-p {target}" in result.output


def test_option_output_directory_still_works(tmp_path: Path) -> None:
    target = tmp_path / "sample2"
    result = CliRunner().invoke(main, ["samples", "first-run", "-o", str(target)])
    assert result.exit_code == 0, result.output
    assert (target / "inventory.json").is_file()


def test_positional_and_option_must_agree(tmp_path: Path) -> None:
    result = CliRunner().invoke(main, ["samples", "first-run", str(tmp_path / "a"), "-o", str(tmp_path / "b")])
    assert result.exit_code == 2
    assert "either" in result.output
