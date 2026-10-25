"""NVD window progress events and the wall-clock budget, under a fake clock and the offline NVD fake."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from agent_bom.db import sync_nvd_window
from agent_bom.db.schema import init_db
from agent_bom.db.sync import sync_db
from tests._nvd_window_fake import FakeNvdWindow

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

pytestmark = pytest.mark.real_vuln_db_sync


class _FakeClock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += max(0.0, seconds)


def _pool(days: int = 13) -> list[tuple[str, datetime]]:
    now = datetime.now(timezone.utc)
    return [(f"CVE-2026-{7000 + day}", now - timedelta(days=day, hours=1)) for day in range(days)]


def _sync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, key: str | None, budget: float | None = None, env_budget: str | None = None
) -> tuple[list[tuple], FakeNvdWindow, _FakeClock]:
    if key is None:
        monkeypatch.delenv("NVD_API_KEY", raising=False)
    else:
        monkeypatch.setenv("NVD_API_KEY", key)
    if env_budget is None:
        monkeypatch.delenv("AGENT_BOM_NVD_TIME_BUDGET_SECONDS", raising=False)
    else:
        monkeypatch.setenv("AGENT_BOM_NVD_TIME_BUDGET_SECONDS", env_budget)
    clock = _FakeClock()
    monkeypatch.setattr(sync_nvd_window, "_clock", clock)
    events: list[tuple] = []

    def progress(source: str, phase: str, current: int, total: int | None, detail: str | None = None) -> None:
        events.append((source, phase, current, total, detail))

    fake = FakeNvdWindow(_pool())
    with patch("agent_bom.http_client.fetch_json", side_effect=fake), patch("time.sleep", side_effect=clock.sleep):
        sync_db(path=tmp_path / "vulns.db", sources=["nvd"], nvd_url=_NVD_URL, progress=progress, nvd_time_budget=budget)
    return events, fake, clock


def _meta(tmp_path: Path) -> dict:
    conn = init_db(tmp_path / "vulns.db")
    try:
        return json.loads(conn.execute("SELECT metadata_json FROM sync_meta WHERE source = 'nvd'").fetchone()[0])
    finally:
        conn.close()


def _stored(tmp_path: Path) -> set[str]:
    conn = init_db(tmp_path / "vulns.db")
    try:
        return {row[0] for row in conn.execute("SELECT id FROM vulns WHERE id LIKE 'CVE-2026-7%'")}
    finally:
        conn.close()


def test_keyless_window_reports_slices_records_and_rate_waits_in_order(tmp_path, monkeypatch) -> None:
    events, _, _ = _sync(tmp_path, monkeypatch, key=None)

    phases = [event[1] for event in events]
    assert phases[0] == "start" and phases[-1] == "complete"
    slices = [event for event in events if event[1] == "slice"]
    records = [event for event in events if event[1] == "records"]
    waits = [event for event in events if event[1] == "rate_wait"]
    assert len(slices) >= 14
    assert [event[2] for event in slices] == list(range(1, len(slices) + 1))
    assert all(event[3] == len(slices) for event in slices)
    # Newest slice first, each labelled with its date.
    dates = [event[4] for event in slices]
    assert dates == sorted(dates, reverse=True)
    assert all(len(date) == 10 for date in dates)
    # Records are cumulative and never run ahead of the slice they belong to.
    assert [event[2] for event in records] == sorted(event[2] for event in records)
    assert records[-1][2] == 13
    assert phases.index("slice") < phases.index("records")
    # Five requests per 30 s keyless: the sixth request waits, and says so.
    assert waits and all(event[2] > 0 for event in waits)
    assert phases.index("rate_wait") > [i for i, phase in enumerate(phases) if phase == "slice"][4]


def test_time_budget_stops_partial_with_resume_and_a_second_run_finishes(tmp_path, monkeypatch) -> None:
    events, first_fake, _ = _sync(tmp_path, monkeypatch, key=None, budget=45)

    meta = _meta(tmp_path)
    assert meta["status"] == "partial"
    assert meta["partial_reason"] == "time_budget"
    assert meta["sync_failed"] is False
    assert meta["time_budget_seconds"] == 45
    assert meta["covered"], "the checkpoint must record what the run held"
    assert events[-1][1] == "partial"
    held = _stored(tmp_path)
    assert 0 < len(held) < 13
    assert not [call for call in first_fake.calls if "cveId" in call], "no backfill after the budget is spent"

    _, second_fake, _ = _sync(tmp_path, monkeypatch, key=None)

    assert _stored(tmp_path) == {cve for cve, _ in _pool()}
    assert _meta(tmp_path)["status"] == "synced"
    refetched = {cve for cve in second_fake.served} & held
    assert not refetched, "the second run resumes past what the first one held"


def test_env_budget_applies_and_zero_disables(tmp_path, monkeypatch) -> None:
    (tmp_path / "a").mkdir()
    _sync(tmp_path / "a", monkeypatch, key=None, env_budget="45")
    assert _meta(tmp_path / "a")["partial_reason"] == "time_budget"
    (tmp_path / "b").mkdir()
    _sync(tmp_path / "b", monkeypatch, key=None, env_budget="0")
    assert _meta(tmp_path / "b")["status"] == "synced"


def test_keyed_run_without_budget_is_unchanged(tmp_path, monkeypatch) -> None:
    events, fake, _ = _sync(tmp_path, monkeypatch, key="nvd-test-key")

    meta = _meta(tmp_path)
    assert meta["status"] == "synced"
    assert meta["partial_reason"] is None
    assert meta["time_budget_seconds"] is None
    assert _stored(tmp_path) == {cve for cve, _ in _pool()}
    # 120 day slices at 50 requests per 30 s: waits are reported, the budget never cuts the run.
    assert len([event for event in events if event[1] == "slice"]) >= 120
    assert len([event for event in events if event[1] == "rate_wait"]) == 2
    assert not [call for call in fake.calls if "cveId" in call]


def _cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *args: str):
    from click.testing import CliRunner

    from agent_bom.cli._db import db_cmd

    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_BOM_NVD_TIME_BUDGET_SECONDS", raising=False)
    clock = _FakeClock()
    monkeypatch.setattr(sync_nvd_window, "_clock", clock)
    with patch("agent_bom.http_client.fetch_json", side_effect=FakeNvdWindow(_pool())), patch("time.sleep", side_effect=clock.sleep):
        return CliRunner().invoke(db_cmd, ["update", "--source", "nvd", "--path", str(tmp_path / "vulns.db"), *args])


def test_cli_shows_nvd_window_progress_and_the_budget_resume_hint(tmp_path, monkeypatch) -> None:
    result = _cli(tmp_path, monkeypatch, "--nvd-time-budget", "45")

    assert result.exit_code == 0, result.output
    assert "live progress follows" not in result.output
    assert "nvd: slice 1/" in result.output
    assert "records read" in result.output
    assert "rate limit: waiting 30s" in result.output
    assert "nvd: PARTIAL (time_budget)" in result.output
    assert "45-second time budget" in result.output
    assert "agent-bom db update --source nvd" in result.output
    assert "--nvd-time-budget" in result.output


def test_cli_rejects_a_negative_budget(tmp_path, monkeypatch) -> None:
    result = _cli(tmp_path, monkeypatch, "--nvd-time-budget", "-1")
    assert result.exit_code != 0
    assert "--nvd-time-budget" in result.output
