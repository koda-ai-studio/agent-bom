"""Constructing a current-estate store sweeps stale sibling projection caches without touching its own."""

from __future__ import annotations

import gc
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from agent_bom import config
from agent_bom.api.current_graph import CurrentGraphStore, _current_graph_store, current_graph_store
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.store import InMemoryJobStore
from agent_bom.storage import projection_cache
from tests.api import test_current_graph_estate as estate_helpers

estate = estate_helpers.estate
record = estate_helpers.record
DAY = 86_400
_STORE_HOLDER = """
import sys
from agent_bom.api.current_graph import CurrentGraphStore
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.store import InMemoryJobStore
store = CurrentGraphStore(SQLiteGraphStore(sys.argv[1]), InMemoryJobStore())
print(store._cache_path, flush=True)
sys.stdin.read()
"""


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


def _new_store(tmp_path: Path, name: str) -> CurrentGraphStore:
    return CurrentGraphStore(SQLiteGraphStore(str(tmp_path / f"{name}.db")), InMemoryJobStore())


def _age(path: Path, days: int = 30) -> None:
    stamp = time.time() - days * DAY
    for member in projection_cache.cache_files(path):
        if member.exists():
            os.utime(member, (stamp, stamp))


def test_a_live_store_keeps_its_file_and_data_after_more_than_keep_latest_newer_stores(estate, cache_dir, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "CURRENT_ESTATE_CACHE_MAX_AGE_DAYS", 14)
    record(estate, 8, "repo-a", "package-a")
    live = CurrentGraphStore(estate[1], estate[0])
    assert set(live.load_graph(tenant_id="history-tenant").nodes) == {"package-a"}
    active = Path(live._cache_path)
    _age(active)

    newer = [_new_store(tmp_path, f"other-{index}") for index in range(config.CURRENT_ESTATE_CACHE_KEEP_LATEST + 4)]

    assert active.exists()
    assert all(Path(store._cache_path).exists() for store in newer), "every live store keeps its file"
    assert set(live.load_graph(tenant_id="history-tenant").nodes) == {"package-a"}
    # A new evidence revision forces a rebuild through the live store's own file.
    record(estate, 9, "repo-b", "package-b")
    assert set(live.load_graph(tenant_id="history-tenant").nodes) == {"package-a", "package-b"}


def test_an_abandoned_store_file_is_swept_once_nothing_holds_it(cache_dir, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "CURRENT_ESTATE_CACHE_MAX_AGE_DAYS", 14)
    abandoned = _new_store(tmp_path, "abandoned")
    path = Path(abandoned._cache_path)
    del abandoned
    gc.collect()
    _age(path)

    _new_store(tmp_path, "next")

    assert not path.exists()
    assert not projection_cache.lease_path(path).exists()


def test_close_releases_the_lease_and_is_repeatable(cache_dir, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "CURRENT_ESTATE_CACHE_MAX_AGE_DAYS", 14)
    store = _new_store(tmp_path, "closed")
    path = Path(store._cache_path)
    _age(path)
    sweep = {"keep_latest": 0, "max_age_days": 14}
    assert projection_cache.sweep_projection_cache(cache_dir, active=None, dry_run=True, **sweep) == []

    store.close()
    store.close()

    assert projection_cache.sweep_projection_cache(cache_dir, active=None, dry_run=True, **sweep) == [path]


def test_lru_eviction_releases_the_evicted_stores_lease(cache_dir, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "CURRENT_ESTATE_CACHE_MAX_AGE_DAYS", 14)
    _current_graph_store.cache_clear()
    backing = [SQLiteGraphStore(str(tmp_path / f"lru-{index}.db")) for index in range(9)]
    jobs = InMemoryJobStore()
    evicted = Path(current_graph_store(backing[0], jobs)._cache_path)
    _age(evicted)
    sweep = {"keep_latest": 0, "max_age_days": 14}
    assert evicted not in projection_cache.sweep_projection_cache(cache_dir, active=None, dry_run=True, **sweep)

    kept = [current_graph_store(store, jobs) for store in backing[1:]]
    gc.collect()

    assert evicted in projection_cache.sweep_projection_cache(cache_dir, active=None, dry_run=True, **sweep)
    assert all(Path(store._cache_path).exists() for store in kept)
    _current_graph_store.cache_clear()


@pytest.mark.skipif(os.name == "nt", reason="uses /dev/fd")
def test_repeatedly_building_and_dropping_stores_does_not_grow_descriptors(cache_dir, tmp_path):
    def churn(prefix: str) -> None:
        for index in range(40):
            _new_store(tmp_path, f"{prefix}-{index}")
        gc.collect()

    churn("warm")
    baseline = len(os.listdir("/dev/fd"))
    churn("measured")
    assert len(os.listdir("/dev/fd")) <= baseline + 2


def test_store_falls_back_to_a_private_cache_when_no_lease_can_be_had(cache_dir, monkeypatch, tmp_path):
    def busy(*args, **kwargs):
        raise TimeoutError("a sweep is stuck")

    monkeypatch.setattr(projection_cache, "acquire_projection_lease", busy)

    store = _new_store(tmp_path, "contended")

    assert Path(store._cache_path).parent != cache_dir
    assert Path(store._cache_path).name == "projection.db"


def test_a_store_in_another_process_blocks_the_sweep_until_it_is_killed(cache_dir, tmp_path):
    holder = subprocess.Popen(
        [sys.executable, "-c", _STORE_HOLDER, str(tmp_path / "remote.db")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONPATH": str(Path(projection_cache.__file__).resolve().parents[2])},
    )
    try:
        assert holder.stdout is not None
        path = Path(holder.stdout.readline().strip())
        assert path.parent == cache_dir
        _age(path)
        sweep = {"keep_latest": 0, "max_age_days": 14}

        assert projection_cache.sweep_projection_cache(cache_dir, active=None, dry_run=True, **sweep) == []
        assert projection_cache.sweep_projection_cache(cache_dir, active=None, **sweep) == []
        assert path.exists()

        holder.kill()
        holder.wait(timeout=30)
        assert projection_cache.sweep_projection_cache(cache_dir, active=None, **sweep) == [path]
        assert not path.exists()
    finally:
        holder.kill()
        holder.communicate(timeout=30)
