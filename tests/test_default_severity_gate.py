"""The CLI and the GitHub Action gate on the same default severity, so a repo never passes locally and fails in CI."""

from __future__ import annotations

import inspect
from pathlib import Path

import yaml

from agent_bom.cli.agents.scan_pipeline import prepare

ROOT = Path(__file__).resolve().parents[1]


def test_cli_default_gate_matches_the_action() -> None:
    action_default = yaml.safe_load((ROOT / "action.yml").read_text())["inputs"]["severity-threshold"]["default"]
    assert prepare.DEFAULT_FAIL_ON_SEVERITY == action_default == "high"


def test_default_and_ci_preset_both_use_the_shared_default() -> None:
    source = inspect.getsource(prepare._apply_presets_and_modes)
    assert source.count("DEFAULT_FAIL_ON_SEVERITY") == 2
    assert '"critical"' not in source
