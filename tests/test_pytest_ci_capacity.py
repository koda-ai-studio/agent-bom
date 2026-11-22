from pathlib import Path

import pytest

from scripts import ci_pytest_workers, ci_shard_balance
from scripts.ci_pytest_workers import worker_count
from scripts.pytest_ci_plan import plan_shards


def test_timed_shards_balance_wall_time_under_memory_worker_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ci_shard_balance, "ROOT", tmp_path, raising=False)
    durations = {tmp_path / "tests/test_demo_estate_bootstrap_lifecycle.py": 300.0}
    durations.update({tmp_path / f"tests/test_regular_{i}.py": 100.0 for i in range(11)})
    for path in durations:
        path.parent.mkdir(exist_ok=True)
        path.write_text("")
    shards = plan_shards(durations, total=2, durations=durations)
    wall = [sum(durations[p] for p in shard) / worker_count([f"tests/{p.name}" for p in shard], cpus=4) for shard in shards]
    assert max(wall) <= 200
    assert sorted(p for shard in shards for p in shard) == sorted(durations)
    assert shards == plan_shards(reversed(durations), total=2, durations=durations)


@pytest.mark.parametrize("absolute", [False, True])
def test_nested_memory_heavy_module_keeps_worker_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, absolute: bool) -> None:
    monkeypatch.setattr(ci_shard_balance, "ROOT", tmp_path, raising=False)
    nested = "tests/demo/test_bootstrap_lifecycle.py"
    monkeypatch.setattr(ci_pytest_workers, "MEMORY_HEAVY_MODULES", frozenset({nested}))
    root = tmp_path if absolute else Path()
    weights = {root / nested: 300.0}
    weights.update({root / f"tests/test_regular_{i}.py": 100.0 for i in range(11)})
    shards = ci_shard_balance.balance_shards(weights, total=2, capacity_aware=True)

    def names(shard: list[Path]) -> list[str]:
        return [p.relative_to(tmp_path).as_posix() if p.is_absolute() else p.as_posix() for p in shard]

    heavy = next(shard for shard in shards if root / nested in shard)
    assert worker_count(names(heavy), cpus=4) == 3
    wall = [sum(weights[p] for p in shard) / worker_count(names(shard), cpus=4) for shard in shards]
    assert max(wall) <= 200
    assert sorted(p for shard in shards for p in shard) == sorted(weights)
