"""Stale current-estate projection caches are bounded by count and age; the active one is never removed."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from agent_bom.storage import projection_cache

DAY = 86_400.0
NOW = 1_800_000_000.0


def _touch(directory: Path, name: str, *, age_days: float, siblings: bool = False) -> Path:
    path = directory / name
    path.write_bytes(b"x" * 16)
    stamp = NOW - age_days * DAY
    os.utime(path, (stamp, stamp))
    if siblings:
        for suffix in ("-wal", "-shm"):
            sibling = directory / f"{name}{suffix}"
            sibling.write_bytes(b"w")
            os.utime(sibling, (stamp, stamp))
    return path


def _sweep(directory: Path, **overrides):
    options = {"active": None, "keep_latest": 2, "max_age_days": 14, "now": NOW}
    options.update(overrides)
    return projection_cache.sweep_projection_cache(directory, **options)


def test_sweep_tolerates_a_missing_directory(tmp_path):
    assert _sweep(tmp_path / "absent") == []


def test_sweep_keeps_the_newest_files_and_removes_the_rest_with_siblings(tmp_path):
    newest = _touch(tmp_path, "a.db", age_days=1)
    second = _touch(tmp_path, "b.db", age_days=2, siblings=True)
    third = _touch(tmp_path, "c.db", age_days=3, siblings=True)
    fourth = _touch(tmp_path, "d.db", age_days=4)
    _touch(tmp_path, "notes.txt", age_days=40)
    nested = tmp_path / "nested"
    nested.mkdir()
    _touch(nested, "deep.db", age_days=40)

    removed = _sweep(tmp_path, keep_latest=2)

    assert removed == [third, fourth]
    assert newest.exists() and second.exists()
    assert (tmp_path / "b.db-wal").exists() and (tmp_path / "b.db-shm").exists()
    assert not third.exists() and not (tmp_path / "c.db-wal").exists() and not (tmp_path / "c.db-shm").exists()
    assert not fourth.exists()
    assert (tmp_path / "notes.txt").exists() and (nested / "deep.db").exists()


def test_sweep_removes_files_older_than_max_age_even_within_keep_latest(tmp_path):
    fresh = _touch(tmp_path, "fresh.db", age_days=1)
    old = _touch(tmp_path, "old.db", age_days=15)

    assert _sweep(tmp_path, keep_latest=8, max_age_days=14) == [old]
    assert fresh.exists() and not old.exists()


@pytest.mark.parametrize("max_age_days", [0, -1])
def test_non_positive_max_age_disables_the_age_rule(tmp_path, max_age_days):
    old = _touch(tmp_path, "old.db", age_days=400)

    assert _sweep(tmp_path, keep_latest=8, max_age_days=max_age_days) == []
    assert old.exists()


def test_sweep_never_removes_the_active_projection_or_its_siblings(tmp_path):
    active = _touch(tmp_path, "active.db", age_days=100, siblings=True)
    newer = _touch(tmp_path, "newer.db", age_days=1)
    stale = _touch(tmp_path, "stale.db", age_days=50)

    assert _sweep(tmp_path, active=active, keep_latest=1, max_age_days=14) == [stale]
    assert active.exists() and (tmp_path / "active.db-wal").exists() and (tmp_path / "active.db-shm").exists()
    assert newer.exists()


def test_dry_run_reports_candidates_without_deleting(tmp_path):
    _touch(tmp_path, "keep.db", age_days=1)
    stale = _touch(tmp_path, "stale.db", age_days=30, siblings=True)

    assert _sweep(tmp_path, dry_run=True) == [stale]
    assert stale.exists() and (tmp_path / "stale.db-wal").exists()


def test_last_use_is_the_newest_of_the_file_and_its_wal_siblings(tmp_path):
    busy = _touch(tmp_path, "busy.db", age_days=40, siblings=True)
    wal = tmp_path / "busy.db-wal"
    os.utime(wal, (NOW - DAY, NOW - DAY))

    assert _sweep(tmp_path, keep_latest=8, max_age_days=14) == []
    assert busy.exists()


def test_a_file_that_cannot_be_removed_is_not_reported_as_removed(tmp_path, monkeypatch):
    stale = _touch(tmp_path, "stale.db", age_days=30)
    stuck = _touch(tmp_path, "stuck.db", age_days=31)
    real_unlink = Path.unlink

    def unlink(self: Path, missing_ok: bool = False) -> None:
        if self.name.startswith("stuck.db"):
            raise PermissionError("busy")
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", unlink)

    assert _sweep(tmp_path, keep_latest=0) == [stale]
    assert stuck.exists() and not stale.exists()


def test_a_file_that_cannot_be_stated_is_left_alone(tmp_path, monkeypatch):
    stale = _touch(tmp_path, "stale.db", age_days=30)
    real_stat = Path.stat

    def stat(self: Path, *, follow_symlinks: bool = True):
        if self.name == "stale.db":
            raise OSError("unreadable")
        return real_stat(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", stat)

    assert _sweep(tmp_path, keep_latest=0) == []
    assert os.path.exists(stale)


def test_cache_path_keeps_the_established_file_naming(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    locator = projection_cache.sqlite_locator(tmp_path / "graph.db")
    legacy = hashlib.sha256(json.dumps(locator, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()[:24]

    assert projection_cache.cache_path_for(locator) == tmp_path / "current-estate-cache" / f"{legacy}.db"
    assert locator == "sqlite:" + str((tmp_path / "graph.db").resolve())


@pytest.mark.parametrize(
    ("env", "expect_postgres"),
    [
        ({}, False),
        ({"AGENT_BOM_POSTGRES_URL": "postgresql://user@host/db"}, True),
        ({"AGENT_BOM_DB": "postgres://user@host/db"}, True),
        ({"AGENT_BOM_DB": "/tmp/control-plane.db"}, False),
    ],
)
def test_configured_locator_agrees_with_control_plane_backend_selection(tmp_path, monkeypatch, env, expect_postgres):
    from agent_bom.api.storage_schema import postgres_deployment_configured

    for name in ("AGENT_BOM_POSTGRES_URL", "AGENT_BOM_DB"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    locator = projection_cache.configured_locator(tmp_path / "graph.db")

    assert postgres_deployment_configured() is expect_postgres
    assert locator.startswith("postgres:") is expect_postgres
    if expect_postgres:
        assert locator == "postgres:" + next(iter(env.values()))
    else:
        assert locator == projection_cache.sqlite_locator(tmp_path / "graph.db")
