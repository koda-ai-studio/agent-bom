"""Constructing a current-estate store sweeps stale sibling projection caches without touching its own."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from agent_bom import config
from agent_bom.api.current_graph import CurrentGraphStore
from agent_bom.storage import projection_cache
from tests.api import test_current_graph_estate as estate_helpers

estate = estate_helpers.estate
record = estate_helpers.record
DAY = 86_400


def _stale(directory: Path, count: int, *, age_days: int) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for index in range(count):
        path = directory / f"{index:024x}.db"
        path.write_bytes(b"x")
        stamp = time.time() - age_days * DAY - index
        os.utime(path, (stamp, stamp))
        paths.append(path)
    return paths


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    return projection_cache.cache_directory()


def test_store_construction_removes_projections_beyond_keep_latest(estate, cache_dir, monkeypatch):
    monkeypatch.setattr(config, "CURRENT_ESTATE_CACHE_MAX_AGE_DAYS", 0)
    stale = _stale(cache_dir, config.CURRENT_ESTATE_CACHE_KEEP_LATEST + 2, age_days=1)

    store = CurrentGraphStore(estate[1], estate[0])

    active = Path(store._cache_path)
    assert active.parent == cache_dir and active.exists()
    surviving = sorted(p for p in cache_dir.glob("*.db"))
    assert active in surviving
    assert len(surviving) == config.CURRENT_ESTATE_CACHE_KEEP_LATEST
    assert not stale[-1].exists() and not stale[-2].exists()
    assert stale[0].exists()


def test_store_construction_removes_projections_older_than_the_age_cap(estate, cache_dir, monkeypatch):
    monkeypatch.setattr(config, "CURRENT_ESTATE_CACHE_MAX_AGE_DAYS", 14)
    (old,) = _stale(cache_dir, 1, age_days=15)
    (recent,) = _stale(cache_dir / "tmp", 1, age_days=1)
    recent = recent.rename(cache_dir / "recent.db")

    CurrentGraphStore(estate[1], estate[0])

    assert not old.exists()
    assert recent.exists()


def test_store_construction_keeps_its_own_projection_and_reuses_it(estate, cache_dir, monkeypatch):
    monkeypatch.setattr(config, "CURRENT_ESTATE_CACHE_MAX_AGE_DAYS", 14)
    record(estate, 8, "repo-a", "package-a")
    first = CurrentGraphStore(estate[1], estate[0])
    first.load_graph(tenant_id="history-tenant")
    active = Path(first._cache_path)
    stamp = time.time() - 30 * DAY
    for path in (active, Path(f"{active}-wal"), Path(f"{active}-shm")):
        if path.exists():
            os.utime(path, (stamp, stamp))

    restarted = CurrentGraphStore(estate[1], estate[0])

    assert Path(restarted._cache_path) == active
    assert active.exists()
    assert set(restarted.load_graph(tenant_id="history-tenant").nodes) == {"package-a"}


def test_sweep_failure_never_blocks_store_construction(estate, cache_dir, monkeypatch):
    def explode(*args, **kwargs):
        raise RuntimeError("sweep broke")

    monkeypatch.setattr("agent_bom.storage.projection_cache.sweep_projection_cache", explode)

    store = CurrentGraphStore(estate[1], estate[0])

    assert Path(store._cache_path).exists()
