"""The live Postgres contract stays exhaustive on isolated, bounded runners."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_postgres_partitions_are_complements_without_fail_fast() -> None:
    job = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]["postgres-integration"]
    assert job["strategy"]["fail-fast"] is False
    assert job["strategy"]["matrix"]["selection"] == ["test_postgres_integration", "not test_postgres_integration"]
    assert job["timeout-minutes"] == 12
    assert "postgres" in job["services"]  # Each matrix runner owns its database.
    step = next(step for step in job["steps"] if step.get("name") == "Run real Postgres storage contract")
    assert '-k "${{ matrix.selection }}"' in step["run"]
    assert "-n 0" in step["run"]  # DDL/role tests within a database remain serial.
    assert not job.get("continue-on-error", False)
    assert not step.get("continue-on-error", False)
