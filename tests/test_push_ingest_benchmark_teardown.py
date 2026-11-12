"""The push-ingest benchmark finishes the work a commit starts before deleting its database.

A pushed job reads ``stored`` before its worker records the posture trend and
schedules warm-ups. The nightly benchmark used to delete its temporary control
plane at that point, so the still-running worker failed with ``no such table``
and the directory cleanup raced its writes. Post-commit work is slowed here so
the race is deterministic.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_WRAPPER = """
import runpy, sys, time
sys.path.insert(0, {src!r})
sys.path.insert(0, {root!r})
from agent_bom.api import push_ingest_worker

original = push_ingest_worker._record_push_trend

def slow_post_commit(*args, **kwargs):
    time.sleep(2.0)
    original(*args, **kwargs)
    print("post-commit work finished", file=sys.stderr, flush=True)

push_ingest_worker._record_push_trend = slow_post_commit
sys.argv = [{script!r}, "--agents", "5", "--readers", "2", "--health-p99-ms", "100000"]
runpy.run_path({script!r}, run_name="__main__")
"""


def test_benchmark_drains_a_live_post_commit_worker_before_cleanup(tmp_path):
    script = str(ROOT / "scripts" / "run_push_ingest_benchmark.py")
    wrapper = _WRAPPER.format(src=str(ROOT / "src"), root=str(ROOT), script=script)
    env = {key: value for key, value in os.environ.items() if not key.startswith("AGENT_BOM_DB")}
    env.update({"TMPDIR": str(tmp_path), "PYTHONPATH": str(ROOT / "src")})
    result = subprocess.run([sys.executable, "-c", wrapper], capture_output=True, text=True, timeout=300, env=env, check=False)
    assert result.returncode == 0, result.stderr[-4000:]
    assert "post-commit work finished" in result.stderr
    for failure in ("Traceback", "Directory not empty", "Unhandled API scan worker failure", "no such table", "unable to open database"):
        assert failure not in result.stderr, result.stderr[-4000:]
    measurement = json.loads(result.stdout.strip().splitlines()[-1])
    assert measurement["ingest_status"] == "stored" and measurement["jobs_stored"] == 1
    assert not list(tmp_path.glob("push-bench-*"))


def test_drain_reports_nothing_busy_when_no_work_was_started():
    sys.path.insert(0, str(ROOT))
    from scripts.run_push_ingest_benchmark import drain_background_work

    assert drain_background_work(timeout=5.0) == []
