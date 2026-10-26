"""Measured scan-scale contract: a 40,000-package offline manifest scan.

Runs the real CLI in a child process against a seeded local vulnerability DB
and asserts it completes within absolute wall-clock and peak-RSS budgets with
every package and every seeded advisory in the report. Budgets leave headroom
over workstation measurements (docs/perf/image-scan-end-to-end.md) while
catching quadratic work over the package list.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_bom.db.schema import init_db

pytestmark = [pytest.mark.slow, pytest.mark.scan_performance]

PACKAGE_COUNT = 40_000
ADVISORY_COUNT = 200
WALL_BUDGET_S = 300.0
PEAK_RSS_BUDGET_MB = 1_000

_CHILD = """
import resource, sys
from agent_bom.cli import main
try:
    main(sys.argv[1:], standalone_mode=False)
except SystemExit:
    pass
finally:
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    sys.stderr.write(f"\\nPEAK_RSS_BYTES={rss if sys.platform == 'darwin' else rss * 1024}\\n")
"""


def _write_lockfile(project: Path) -> None:
    project.mkdir()
    packages: dict[str, dict] = {"": {"name": "bench-app", "version": "1.0.0"}}
    for i in range(PACKAGE_COUNT):
        packages[f"node_modules/bench-pkg-{i}"] = {"version": f"1.{i % 50}.{i % 7}"}
    (project / "package.json").write_text(json.dumps({"name": "bench-app", "version": "1.0.0"}))
    (project / "package-lock.json").write_text(json.dumps({"name": "bench-app", "lockfileVersion": 3, "packages": packages}))


def _seed_db(path: Path) -> None:
    conn = init_db(path)
    try:
        for i in range(ADVISORY_COUNT):
            vuln_id = f"GHSA-bnch-{i:04d}-0000"
            conn.execute(
                "INSERT INTO vulns(id,summary,severity,cvss_score,fixed_version,aliases,source) VALUES (?,?,?,?,?,?,'ghsa')",
                (vuln_id, f"bench advisory {i}", "high", 7.5, "9.0.0", ""),
            )
            conn.execute(
                "INSERT INTO affected(vuln_id,ecosystem,package_name,introduced,fixed,last_affected) VALUES (?,?,?,?,?,'')",
                (vuln_id, "npm", f"bench-pkg-{i}", "0", "9.0.0"),
            )
        conn.execute(
            "INSERT INTO sync_meta(source,last_synced,record_count) VALUES ('osv',?,?)",
            (datetime.now(timezone.utc).isoformat(), ADVISORY_COUNT),
        )
        conn.commit()
    finally:
        conn.close()


def test_40k_package_offline_manifest_scan_is_bounded(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_lockfile(project)
    db_path = Path.home() / "scan-scale-vulns.db"
    _seed_db(db_path)
    report_path = tmp_path / "report.json"
    env = {**os.environ, "AGENT_BOM_DB_PATH": str(db_path), "AGENT_BOM_CONFIG": str(tmp_path / "no-config.toml")}
    args = ["scan", "--offline", "-p", str(project), "--format", "json", "--output", str(report_path)]

    started = time.monotonic()
    child = subprocess.run([sys.executable, "-c", _CHILD, *args], env=env, capture_output=True, text=True, timeout=900, check=False)
    elapsed = time.monotonic() - started

    peak = [line for line in child.stderr.splitlines() if line.startswith("PEAK_RSS_BYTES=")]
    assert peak, child.stderr[-2000:]
    peak_mb = int(peak[-1].split("=", 1)[1]) / (1024 * 1024)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    findings = [f for f in report["findings"] if f["finding_type"] == "CVE"]

    assert report["summary"]["total_packages"] == PACKAGE_COUNT
    assert len(findings) == ADVISORY_COUNT
    assert {f["evidence"]["package_name"] for f in findings} == {f"bench-pkg-{i}" for i in range(ADVISORY_COUNT)}
    assert elapsed <= WALL_BUDGET_S, f"40k-package offline scan took {elapsed:.1f}s (budget {WALL_BUDGET_S}s)"
    assert peak_mb <= PEAK_RSS_BUDGET_MB, f"40k-package offline scan peaked at {peak_mb:.0f} MiB (budget {PEAK_RSS_BUDGET_MB} MiB)"
