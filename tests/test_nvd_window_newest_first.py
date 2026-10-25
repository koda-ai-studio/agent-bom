"""A capped NVD window keeps the newest CVEs, reports partial, and resumes the older tail."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from agent_bom.db.schema import init_db
from agent_bom.db.sync import sync_nvd_incremental
from tests._nvd_window_fake import FakeNvdWindow

_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _pool(count: int, *, span_days: float, newest: str = "CVE-2026-109618") -> list[tuple[str, datetime]]:
    now = datetime.now(timezone.utc)
    step = timedelta(days=span_days) / count
    rows = [(f"CVE-2026-2{index:05d}", now - timedelta(hours=1) - step * (index + 1)) for index in range(count - 1)]
    return [(newest, now - timedelta(minutes=30)), *rows]


def _meta(conn) -> dict:
    return json.loads(conn.execute("SELECT metadata_json FROM sync_meta WHERE source = 'nvd'").fetchone()[0])


def _ids(conn) -> set[str]:
    return {row[0] for row in conn.execute("SELECT id FROM vulns WHERE source = 'nvd'")}


def _run(conn, fake: FakeNvdWindow, **kwargs) -> int:
    with patch("agent_bom.http_client.fetch_json", side_effect=fake), patch("time.sleep"):
        return sync_nvd_incremental(conn, url=_URL, **kwargs)


def test_capped_run_ingests_the_newest_cve_and_is_partial() -> None:
    conn = init_db(Path(":memory:"))
    pool = _pool(40, span_days=10)
    fake = FakeNvdWindow(pool)

    _run(conn, fake, max_results=5)

    ids = _ids(conn)
    assert "CVE-2026-109618" in ids
    assert len(ids) == 5
    assert pool[-1][0] not in ids  # the oldest record waits for a later run
    meta = _meta(conn)
    assert meta["status"] == "partial" and meta["partial_reason"] == "truncated"
    assert meta["sync_truncated"] is True
    assert meta["last_modified_end"] == meta["last_modified_start"]


def test_keyed_default_covers_the_whole_window() -> None:
    conn = init_db(Path(":memory:"))
    pool = _pool(2500, span_days=110)
    fake = FakeNvdWindow(pool)

    assert _run(conn, fake, nvd_api_key="test-key") == 2500

    meta = _meta(conn)
    assert meta["status"] == "synced" and meta["max_results"] is None
    assert meta["last_modified_end"] != meta["last_modified_start"]
    assert meta["covered"] == [[meta["last_modified_start"], meta["covered"][0][1]]]
    assert len(meta["covered"]) == 1


@pytest.mark.parametrize("cap", [3, 7])
def test_capped_runs_resume_the_older_tail_without_refetching(cap: int) -> None:
    conn = init_db(Path(":memory:"))
    pool = _pool(30, span_days=12)
    fake = FakeNvdWindow(pool)

    for _ in range(30):
        _run(conn, fake, max_results=cap)
        if _meta(conn)["status"] == "synced":
            break

    assert _meta(conn)["status"] == "synced"
    assert _ids(conn) == {cve_id for cve_id, _ in pool}
    assert len(fake.served) == len(pool), "a covered range or a read prefix was fetched again"

    before = len(fake.calls)
    assert _run(conn, fake, max_results=cap) == 0
    assert len(fake.calls) - before <= 1, "a synced window only fetches the gap since the last run"


@pytest.mark.real_vuln_db_sync
def test_cli_status_and_freshness_say_partial_not_complete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cli._db import db_cmd

    monkeypatch.delenv("NVD_API_KEY", raising=False)
    db_path = tmp_path / "vulns.db"
    fake = FakeNvdWindow(_pool(40, span_days=10))
    with patch("agent_bom.http_client.fetch_json", side_effect=fake), patch("time.sleep"):
        update = CliRunner().invoke(db_cmd, ["update", "--source", "nvd", "--path", str(db_path), "--max-nvd-entries", "5"])

    assert update.exit_code == 0, update.output
    assert "nvd: complete" not in update.output
    assert "nvd: PARTIAL (truncated)" in update.output

    status = CliRunner().invoke(db_cmd, ["status", "--path", str(db_path)])
    assert "partial (truncated)" in status.output

    freshness = CliRunner().invoke(db_cmd, ["freshness", "--path", str(db_path), "--format", "json"])
    body = json.loads(freshness.output)
    assert body["partial_sources"] == [{"source": "NVD", "reason": "truncated"}]
    text = CliRunner().invoke(db_cmd, ["freshness", "--path", str(db_path)])
    assert "NVD sync partial (truncated)" in text.output
