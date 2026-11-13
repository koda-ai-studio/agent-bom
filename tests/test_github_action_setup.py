"""Setup-step contract for ``action.yml``: Python setup and the vuln DB cache."""

from __future__ import annotations

from pathlib import Path

import yaml

from agent_bom.db import schema
from agent_bom.storage import state_home

ROOT = Path(__file__).resolve().parents[1]
STEPS = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))["runs"]["steps"]


def _step(prefix: str) -> dict:
    return next(step for step in STEPS if str(step.get("uses", "")).startswith(prefix))


def test_vuln_db_cache_targets_the_directory_the_cli_reads(monkeypatch) -> None:
    cache = _step("actions/cache@")
    # The action runs without AGENT_BOM_STATE_DIR, so the CLI reads the DB from
    # the default state dir; the test suite pins its own state dir, so resolve
    # the default with that variable unset.
    monkeypatch.delenv(state_home.STATE_DIR_ENV, raising=False)
    default_db = state_home.state_dir() / "db" / "vulns.db"
    expected = "~/" + str(default_db.relative_to(Path.home()))
    assert cache["with"]["path"].strip() == expected
    assert schema._default_db_file() == default_db


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


def test_no_expression_is_interpolated_into_a_run_script() -> None:
    offenders = [step.get("name") or step.get("id") for step in STEPS if "${{" in str(step.get("run", ""))]
    assert offenders == []


def test_inputs_never_become_python_source() -> None:
    import re

    for step in STEPS:
        script = str(step.get("run", ""))
        assert not re.search(r"'\$[A-Z_]+'", script), step.get("name")
