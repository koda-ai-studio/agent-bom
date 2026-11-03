"""An existing report remains intact through the isolated storage profile."""

import json
from pathlib import Path

from scripts.bench.report_volume_bench import measure


def test_existing_report_profile_preserves_full_export_and_tenant_scope(tmp_path):
    path = tmp_path / "report.json"
    original = json.dumps({"agents": [], "findings": [{"id": "one", "evidence": {"partial": True}}], "opaque": [1, 2, 3]})
    path.write_text(original)
    result = measure(Path("src").resolve(), 1, path)
    assert path.read_text() == original
    assert result["generation_ms"] is None
    assert result["full_export_parity"] and result["foreign_tenant_denied"]
    assert result["sqlite_two_identical_snapshot_bytes"] >= result["sqlite_one_snapshot_bytes"]
    assert result["job_row_bytes"] > 0 and result["sqlite_put_ms"] > 0
