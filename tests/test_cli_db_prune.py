"""``agent-bom db prune`` previews by default, deletes only with --yes, and never touches the active projection."""

from __future__ import annotations

import json
import os
import time

import pytest
from click.testing import CliRunner

from agent_bom import config
from agent_bom.cli import main
from agent_bom.storage import projection_cache

DAY = 86_400


@pytest.fixture
def local_state(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(tmp_path / "graph.db"))
    for name in ("AGENT_BOM_POSTGRES_URL", "AGENT_BOM_DB"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(config, "CURRENT_ESTATE_CACHE_MAX_AGE_DAYS", 14)
    directory = projection_cache.cache_directory()
    directory.mkdir(parents=True)
    active = projection_cache.cache_path_for(projection_cache.sqlite_locator(tmp_path / "graph.db"))
    active.write_bytes(b"a" * 64)
    old = time.time() - 30 * DAY
    os.utime(active, (old, old))
    stale = []
    for index in range(config.CURRENT_ESTATE_CACHE_KEEP_LATEST + 3):
        path = directory / f"{index:024x}.db"
        path.write_bytes(b"s" * 1024)
        stamp = time.time() - 20 * DAY - index
        os.utime(path, (stamp, stamp))
        stale.append(path)
    wal = directory / f"{stale[0].name}-wal"
    wal.write_bytes(b"w" * 512)
    os.utime(wal, (old, old))
    return directory, active, stale


def _run(args: list[str]):
    return CliRunner().invoke(main, ["db", "prune", *args])


def test_db_prune_previews_by_default_and_leaves_files(local_state):
    directory, active, stale = local_state

    result = _run([])

    assert result.exit_code == 0, result.output
    assert all(path.exists() for path in stale) and active.exists()
    assert "would remove" in result.output.lower() or "dry run" in result.output.lower()
    assert stale[0].name in result.output
    assert "--yes" in result.output
    assert "agent-bom report prune --apply --compact" in result.output


def test_db_prune_json_lists_each_candidate_with_size_and_age(local_state):
    directory, active, stale = local_state

    result = _run(["--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["dry_run"] is True
    assert payload["directory"] == str(directory)
    assert payload["active"] == str(active)
    assert payload["keep_latest"] == config.CURRENT_ESTATE_CACHE_KEEP_LATEST
    assert payload["max_age_days"] == 14
    listed = {entry["path"]: entry for entry in payload["candidates"]}
    assert set(listed) == {str(path) for path in stale}
    first = listed[str(stale[0])]
    assert first["bytes"] == 1024 + 512
    assert 19 <= first["age_days"] <= 21
    assert payload["total_bytes"] == sum(entry["bytes"] for entry in payload["candidates"])
    assert payload["count"] == len(stale)
    assert "agent-bom report prune --apply --compact" in payload["analytics_mirror"]


def test_db_prune_yes_removes_candidates_and_keeps_the_active_projection(local_state):
    directory, active, stale = local_state

    result = _run(["--yes", "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["dry_run"] is False
    assert payload["count"] == len(stale)
    assert not any(path.exists() for path in stale)
    assert not (directory / f"{stale[0].name}-wal").exists()
    assert active.exists()


def test_db_prune_reports_nothing_to_remove(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))

    result = _run([])

    assert result.exit_code == 0, result.output
    assert "0 file" in result.output or "nothing" in result.output.lower()
