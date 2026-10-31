"""Explicit enrichment must survive quick-profile defaults and CLI forwarding."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli.agents.scan_pipeline import preflight
from agent_bom.cli.agents.scan_pipeline.state import StopScan


@pytest.mark.parametrize("command", ["scan", "fs"])
@pytest.mark.parametrize("enrich,offline,expected", [(True, False, True), (False, False, False), (True, True, False)])
def test_quick_profile_enrichment_precedence(monkeypatch, tmp_path, command, enrich, offline, expected):
    config = tmp_path / "config.toml"
    config.write_text('current_profile = "fast"\n[profiles.fast]\npreset = "quick"\n')
    monkeypatch.setenv("AGENT_BOM_CONFIG", str(config))
    monkeypatch.delenv("AGENT_BOM_PROFILE", raising=False)
    monkeypatch.chdir(tmp_path)
    observed = []
    apply_offline = preflight._apply_offline_mode

    def capture(opts, state):
        apply_offline(opts, state)
        observed.append((opts.enrich, opts.offline))
        raise StopScan

    monkeypatch.setattr(preflight, "_apply_offline_mode", capture)
    args = ["fs", str(tmp_path)] if command == "fs" else ["scan", "--no-discover", "-p", str(tmp_path)]
    if enrich:
        args.append("--enrich")
    if offline:
        args.append("--offline")
    result = CliRunner().invoke(main, args)

    assert result.exit_code == 0, result.output
    assert observed == [(expected, offline)]


def test_explicit_quick_preset_preserves_explicit_enrichment(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    observed = []

    def capture(opts, state):
        observed.append(opts.enrich)
        raise StopScan

    monkeypatch.setattr(preflight, "_apply_offline_mode", capture)
    result = CliRunner().invoke(main, ["scan", "--preset", "quick", "--enrich", "--no-discover", "-p", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert observed == [True]
