from pathlib import Path

from scripts.ci_pytest_workers import worker_count
from scripts.pytest_ci_plan import plan_shards


def test_timed_shards_balance_wall_time_under_memory_worker_cap(tmp_path: Path) -> None:
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
