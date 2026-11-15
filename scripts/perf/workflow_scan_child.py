"""Run the workflow's CLI scan in its own process, as an operator's collector host would.

The control plane's memory limit applies to the API process; the CLI scan runs
elsewhere in a deployment. Scanning inside the measured API process charged the
scan's own peak (and the allocator arenas it never returns) to the API. The
parent reaps this child with ``wait4`` and records its CPU and peak RSS as the
scan stage's own figures.

    python scripts/perf/workflow_scan_child.py SPEC.json

``SPEC.json`` names the inventory, the output report, the vulnerable
``[name, version, advisory]`` triples, the injected upstream failures and the
push ``source_id``. The child writes ``<output>.scan.json`` with the exit code,
the upstream snapshot and any refused non-loopback connection.

It also does the rest of the CLI's client-side work: the push body the CLI
sends (``<output>.push.json``) and the finding rows the harness compares
(``<output>.rows.json``). Parsing the 50-70 MB report and building that body
peaks near 480 MiB of Python heap at 200 agents; in the measured API process it
was charged to the API and pushed the update/delete stage over its budget.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def client_artifacts(output: Path) -> tuple[Path, Path]:
    """Where the child leaves the push body and the finding rows for ``output``."""
    return output.with_name(f"{output.name}.push.json"), output.with_name(f"{output.name}.rows.json")


def write_client_artifacts(output: Path, *, source_id: str) -> None:
    """Write what the CLI would send for ``output`` and the rows the harness compares."""
    from scripts.perf.workflow_profiles import cli_push_body

    report_bytes = output.read_bytes()
    push_path, rows_path = client_artifacts(output)
    rows = json.loads(report_bytes).get("blast_radius") or []
    rows_path.write_text(json.dumps(rows), encoding="utf-8")
    push_path.write_bytes(cli_push_body(report_bytes, source_id=source_id))


def main(spec_path: str) -> int:
    sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
    from scripts.perf.workflow_budget import _run_cli_scan, mocked_upstream, network_guard
    from scripts.perf.workflow_profiles import MockUpstream

    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    vulnerable = {(name, version): advisory for name, version, advisory in spec["vulnerable"]}
    upstream = MockUpstream(vulnerable=vulnerable, fail_first_batches=int(spec.get("fail_first_batches", 0)))
    output = Path(spec["output"])
    with network_guard() as guard, mocked_upstream(upstream):
        exit_code = _run_cli_scan(Path(spec["inventory"]), output)
    if output.exists():
        write_client_artifacts(output, source_id=str(spec["push_source_id"]))
    receipt = {
        "exit_code": exit_code,
        "upstream": upstream.snapshot(),
        "blocked_connections": guard.blocked,
        "blocked_callers": sorted(set(guard.callers)),
    }
    Path(f"{output}.scan.json").write_text(json.dumps(receipt), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
