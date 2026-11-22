"""Deterministic shard balancing using the same worker caps as CI."""

from pathlib import Path

if __package__:
    from .ci_pytest_workers import worker_count
else:
    from ci_pytest_workers import worker_count


ROOT = Path(__file__).resolve().parents[1]


def balance_shards(weights: dict[Path, float], *, total: int, capacity_aware: bool = False) -> list[list[Path]]:
    """Balance projected runtime, retaining the memory-heavy worker limit."""
    shards: list[list[Path]] = [[] for _ in range(total)]
    loads = [0.0] * total
    capacities = [4] * total
    for path in sorted(weights, key=lambda item: (-weights[item], item.as_posix())):
        name = path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else path.as_posix()
        cap = worker_count([name], cpus=4) if capacity_aware else 4
        index = min(range(total), key=lambda candidate: ((loads[candidate] + weights[path]) / min(capacities[candidate], cap), candidate))
        capacities[index] = min(capacities[index], cap)
        shards[index].append(path)
        loads[index] += weights[path]
    return [sorted(shard) for shard in shards]
