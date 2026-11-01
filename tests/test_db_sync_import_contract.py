"""Database sync compatibility exports must work in a fresh interpreter."""

import subprocess
import sys

import pytest


@pytest.mark.real_vuln_db_sync
def test_database_sync_imports_and_normalizes_scores_in_a_fresh_process():
    script = " ".join(
        [
            "from agent_bom.db.sync import _normalize_sync_cvss_score;",
            "assert _normalize_sync_cvss_score(0) == 0.0;",
            "assert _normalize_sync_cvss_score(9.2) == 9.2;",
            "assert _normalize_sync_cvss_score(True) is None",
        ]
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
