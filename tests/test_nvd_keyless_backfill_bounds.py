"""Keyless ``db update`` keeps the per-CVE CVSS backfill small and skips CVEs the window already scored."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from agent_bom.db.schema import init_db
from agent_bom.db.sync import sync_db
from agent_bom.db.sync_nvd_window import KEYLESS_BACKFILL_MAX
from tests._nvd_window_fake import FakeNvdWindow

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_WINDOW_CVE = "CVE-2026-5000"


def _seed(db_path: Path, unscored: int) -> None:
    conn = init_db(db_path)
    try:
        rows = [(f"GHSA-seed-{index}", f"CVE-2025-{1000 + index}") for index in range(unscored)]
        rows.append(("GHSA-window-hit", _WINDOW_CVE))
        conn.executemany(
            "INSERT INTO vulns (id, summary, severity, source, published, modified, cwe_ids, aliases) "
            "VALUES (?, 'seeded', 'unknown', 'osv', '', '', '', ?)",
            rows,
        )
        conn.commit()
    finally:
        conn.close()


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key: str | None) -> tuple[FakeNvdWindow, Path]:
    if key is None:
        monkeypatch.delenv("NVD_API_KEY", raising=False)
    else:
        monkeypatch.setenv("NVD_API_KEY", key)
    db_path = tmp_path / "vulns.db"
    _seed(db_path, unscored=120)
    fake = FakeNvdWindow([(_WINDOW_CVE, datetime.now(timezone.utc) - timedelta(days=1))])
    with patch("agent_bom.http_client.fetch_json", side_effect=fake), patch("time.sleep"):
        sync_db(path=db_path, sources=["nvd"], nvd_url=_NVD_URL)
    return fake, db_path


def _lookups(fake: FakeNvdWindow) -> list[str]:
    return [call["cveId"] for call in fake.calls if "cveId" in call]


def test_keyless_backfill_is_capped_and_skips_window_scored_cves(tmp_path, monkeypatch) -> None:
    fake, db_path = _run(tmp_path, monkeypatch, None)

    lookups = _lookups(fake)
    assert KEYLESS_BACKFILL_MAX == 50
    assert 0 < len(lookups) <= KEYLESS_BACKFILL_MAX
    assert _WINDOW_CVE not in lookups
    conn = init_db(db_path)
    try:
        row = conn.execute("SELECT severity, cvss_score FROM vulns WHERE id = 'GHSA-window-hit'").fetchone()
    finally:
        conn.close()
    assert (row["severity"], row["cvss_score"]) == ("high", 7.5)


def test_keyed_backfill_keeps_the_existing_cap(tmp_path, monkeypatch) -> None:
    fake, _ = _run(tmp_path, monkeypatch, "nvd-test-key")
    assert _lookups(fake) == []
