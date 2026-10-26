"""Every provider command on the legacy ``agent-cloud`` group is also reachable as ``agent-bom cloud <provider>``."""

from __future__ import annotations

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli.cloud import cloud as legacy_cloud


def test_main_cloud_group_exposes_every_legacy_provider_command() -> None:
    main_cloud = main.commands["cloud"]
    missing = sorted(set(legacy_cloud.commands) - set(main_cloud.commands))
    assert missing == []


def test_databricks_is_discoverable_from_the_main_cli() -> None:
    result = CliRunner().invoke(main, ["cloud", "databricks", "--help"])
    assert result.exit_code == 0, result.output
    assert "Databricks" in result.output
