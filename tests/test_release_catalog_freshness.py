"""Release checks must inspect shipped ATLAS data, not an operator cache."""

from __future__ import annotations

import json
import shlex
from datetime import datetime, timezone
from pathlib import Path

import yaml
from click.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]


def test_release_gate_rejects_stale_bundle_with_fresh_local_cache(monkeypatch, tmp_path):
    from agent_bom import atlas_fetch
    from agent_bom.cli._db import db_framework_status

    bundled = tmp_path / "bundled.json"
    cached = tmp_path / "cached.json"
    catalog = {"atlas_version": "test", "techniques": {"AML.T0000": {}}, "tactics": {}}
    bundled.write_text(json.dumps({**catalog, "source": "bundled", "updated_at": "2000-01-01"}))
    cached.write_text(json.dumps({**catalog, "source": "synced", "updated_at": datetime.now(timezone.utc).isoformat()}))
    monkeypatch.setattr(atlas_fetch, "_BUNDLED_CATALOG_PATH", bundled)
    monkeypatch.setenv("AGENT_BOM_ATLAS_CATALOG_PATH", str(cached))
    monkeypatch.setenv("AGENT_BOM_ATLAS_CATALOG_MODE", "auto")
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    steps = workflow["jobs"]["atlas-catalog-freshness-gate"]["steps"]
    gate = next(step for step in steps if step.get("name") == "Verify bundled MITRE ATLAS catalog freshness")
    for key, value in gate.get("env", {}).items():
        monkeypatch.setenv(key, value)
    result = CliRunner().invoke(
        db_framework_status,
        ["--framework", "atlas", "--stale-after-days", "180", "--fail-on-stale", "--format", "json"],
    )
    assert result.exit_code == 1, result.output
    [atlas] = json.loads(result.output)["frameworks"]
    assert atlas["source"] == "bundled"
    assert atlas["status"] == "stale"


def test_preflight_checks_bundled_catalog_before_allowing_tag():
    script = (ROOT / "scripts/preflight_release.sh").read_text()
    commands = [line for line in script.splitlines() if "framework-status" in line]
    assert len(commands) == 1, "Preflight must run the release ATLAS freshness gate"
    args = shlex.split(commands[0])
    assert "AGENT_BOM_ATLAS_CATALOG_MODE=bundled" in args
    assert args[args.index("--framework") + 1] == "atlas"
    assert args[args.index("--stale-after-days") + 1] == "180"
    assert "--fail-on-stale" in args
    assert "||" in args and "fail=1" in args
    assert script.index(commands[0]) < script.rindex("Pre-flight OK")
