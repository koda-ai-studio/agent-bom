#!/usr/bin/env python3
"""Report and stored-job volume on the offline demo estate.

Writes the demo scan's JSON report with the CLI of the selected source tree,
then, in a fresh interpreter on that tree, measures: the report file and its
gzip size, the ``blast_radius`` section, the stored scan-job row
(``encode_job_payload`` when the tree has it, else ``model_dump_json``) with
encode/decode wall time, and the tracemalloc peak of writing the report with
the tree's ``write_json_file``. ``--repeat N`` tiles every top-level list N
times to show how the same shape scales; tiled numbers are synthetic.

Examples:
  uv run python scripts/bench/report_volume_bench.py
  uv run python scripts/bench/report_volume_bench.py --src /tmp/base/src --repeat 20
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

_MEASURE = r"""
import gzip, json, sys, time, tracemalloc
from pathlib import Path
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.storage.jobs import parse_job_payload
from agent_bom.output.json_writer import write_json_file

report_path, repeat, scratch = Path(sys.argv[1]), int(sys.argv[2]), Path(sys.argv[3])
report = json.loads(report_path.read_text())
if repeat > 1:
    report = {k: (v * repeat if isinstance(v, list) else v) for k, v in report.items()}
pretty = (json.dumps(report, indent=2) + "\n").encode()
try:
    from agent_bom.api.job_payload_codec import encode_job_payload
except ImportError:
    encode_job_payload = lambda job: job.model_dump_json()
job = ScanJob(
    job_id="bench", tenant_id="bench", status=JobStatus.DONE, created_at="2026-10-26T00:00:00Z", request=ScanRequest(), result=report
)
started = time.perf_counter()
row = encode_job_payload(job)
encode_ms = (time.perf_counter() - started) * 1000
started = time.perf_counter()
parse_job_payload(row)
decode_ms = (time.perf_counter() - started) * 1000
tracemalloc.start()
write_json_file(report, str(scratch / "report.json"))
write_peak = tracemalloc.get_traced_memory()[1]
tracemalloc.stop()
print(json.dumps({
    "findings": len(report.get("findings", [])),
    "blast_radius_rows": len(report.get("blast_radius", [])),
    "report_bytes": len(pretty),
    "report_gzip6_bytes": len(gzip.compress(pretty, 6)),
    "blast_radius_bytes": len(json.dumps(report.get("blast_radius", []), indent=2)),
    "job_row_bytes": len(row.encode()),
    "job_row_encode_ms": round(encode_ms, 1),
    "job_row_decode_ms": round(decode_ms, 1),
    "write_json_file_peak_bytes": write_peak,
}))
"""


def _env(src: Path | None) -> dict[str, str]:
    env = dict(os.environ)
    if src is not None:
        env["PYTHONPATH"] = str(src)
    return env


def measure(src: Path | None, repeat: int) -> dict:
    with tempfile.TemporaryDirectory(prefix="report-volume-") as scratch:
        report = Path(scratch) / "demo.json"
        cli = [sys.executable, "-c", "from agent_bom.cli import main; main()", "agents", "--demo", "--offline", "--exit-zero"]
        subprocess.run([*cli, "-f", "json", "-o", str(report)], env=_env(src), check=True, capture_output=True)  # noqa: S603
        out = subprocess.run(  # noqa: S603
            [sys.executable, "-c", _MEASURE, str(report), str(repeat), scratch], env=_env(src), check=True, capture_output=True, text=True
        )
        return json.loads(out.stdout.strip().splitlines()[-1])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--src", type=Path, help="source tree to measure (default: the installed package)")
    parser.add_argument("--repeat", type=int, default=1, help="tile top-level lists N times (synthetic scale)")
    args = parser.parse_args()
    result = {"python": platform.python_version(), "machine": platform.machine(), "repeat": args.repeat, **measure(args.src, args.repeat)}
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
