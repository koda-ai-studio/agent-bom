"""``--offline`` with ``--push-url`` is refused before the scan runs, not after it."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from agent_bom.cli import main


def test_offline_push_is_refused_up_front(tmp_path) -> None:
    with patch("agent_bom.cli.agents.scan_pipeline.discovery.run_discovery") as discovery:
        result = CliRunner().invoke(
            main,
            ["scan", "--demo", "--offline", "--push-url", "http://127.0.0.1:9", "-f", "json", "-o", str(tmp_path / "r.json")],
        )
    assert result.exit_code == 2, result.output
    assert "--push-url sends the report over the network" in result.output
    assert "--offline" in result.output
    assert not (tmp_path / "r.json").exists()
    discovery.assert_not_called()
