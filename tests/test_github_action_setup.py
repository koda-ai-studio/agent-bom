"""Setup-step contract for ``action.yml``: Python setup and the vuln DB cache."""

from __future__ import annotations

from pathlib import Path

import yaml

from agent_bom.db import schema

ROOT = Path(__file__).resolve().parents[1]
STEPS = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))["runs"]["steps"]


def _step(prefix: str) -> dict:
    return next(step for step in STEPS if str(step.get("uses", "")).startswith(prefix))


def test_vuln_db_cache_targets_the_directory_the_cli_reads() -> None:
    cache = _step("actions/cache@")
    expected = "~/" + str((schema._DEFAULT_DB_DIR / "vulns.db").relative_to(Path.home()))
    assert cache["with"]["path"].strip() == expected


def test_vuln_db_cache_key_rolls_daily_and_restores_the_last_copy() -> None:
    cache = _step("actions/cache@")
    names = [step.get("id") for step in STEPS]
    bucket = next(step for step in STEPS if step.get("id") == "vulndb-cache-key")
    assert names.index("vulndb-cache-key") < STEPS.index(cache)
    assert "date -u +%Y-%m-%d" in bucket["run"]
    key = cache["with"]["key"]
    assert "${{ steps.vulndb-cache-key.outputs.day }}" in key
    restore = cache["with"]["restore-keys"].strip().splitlines()
    assert restore and key.startswith(restore[0].strip())
    assert "-v1" not in key



def test_setup_python_does_not_require_caller_python_manifests() -> None:
    setup = _step("actions/setup-python@")
    assert "cache" not in setup.get("with", {})
