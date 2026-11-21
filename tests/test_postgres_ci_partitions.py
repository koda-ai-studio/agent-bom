"""The live Postgres contract stays exhaustive on isolated, bounded runners."""

import re
from pathlib import Path

import yaml

from scripts.pytest_ci_plan import load_durations, plan_shards

ROOT = Path(__file__).resolve().parents[1]
STEP = "Run real Postgres storage contract"


def _job() -> dict:
    return yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]["postgres-integration"]


def _step(job: dict) -> dict:
    return next(step for step in job["steps"] if step.get("name") == STEP)


def _suites(run: str) -> list[str]:
    return [token for token in run.replace("\\", " ").split() if token.startswith("tests/") and token.endswith(".py")]


def test_postgres_partitions_are_isolated_runners_without_fail_fast() -> None:
    job = _job()
    partitions = job["strategy"]["matrix"]["partition"]
    assert partitions == list(range(len(partitions))) and len(partitions) >= 2
    assert job["strategy"]["fail-fast"] is False
    assert job["timeout-minutes"] == 12
    assert "postgres" in job["services"]  # Each matrix runner owns its database.
    step = _step(job)
    run = step["run"]
    assert f'--index "${{{{ matrix.partition }}}}" --total {len(partitions)}' in run
    assert '--files "${SUITES[@]}"' in run
    assert "--durations tests/.ci-postgres-durations.json" in run
    assert 'if [ "${#TESTS[@]}" -eq 0 ]; then' in run
    pytest_line = next(line for line in run.splitlines() if "uv run pytest " in line)
    assert "-n 0" in pytest_line  # DDL/role tests within a database remain serial.
    assert " -v " in pytest_line  # Per-test lines let refresh_ci_durations.py measure each suite.
    assert pytest_line.rstrip().endswith('"${TESTS[@]}"')
    assert "-k " not in pytest_line
    assert not job.get("continue-on-error", False)
    assert not step.get("continue-on-error", False)


def test_postgres_partitions_run_every_listed_suite_exactly_once() -> None:
    job = _job()
    total = len(job["strategy"]["matrix"]["partition"])
    run = _step(job)["run"]
    listed = sorted(_suites(run.split("SUITES=(", 1)[1].split(")", 1)[0]))
    assert listed and len(listed) == len(set(listed))
    files = [ROOT / suite for suite in listed]
    durations = load_durations(ROOT / "tests/.ci-postgres-durations.json")
    partitions = plan_shards(files, total=total, durations=durations)
    assert all(partitions)
    assigned = [path.relative_to(ROOT).as_posix() for partition in partitions for path in partition]
    assert sorted(assigned) == listed


def test_postgres_partition_job_name_shows_its_index() -> None:
    assert re.fullmatch(r"Postgres Integration Contract \(\$\{\{ matrix\.partition \}\}/\d+\)", _job()["name"])
