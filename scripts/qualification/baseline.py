#!/usr/bin/env python3
"""Compare measured timings and memory against the committed qualification baseline.

The baseline holds values copied from real hosted-runner runs; nothing is
invented. With no baseline file the run only records. ``--write`` prints a new
baseline from a results directory for review before committing it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import RESULTS_DIR  # noqa: E402

BASELINE_PATH = Path(__file__).resolve().parent / "baseline.json"
_ESTATE_METRICS = {
    "ingest_seconds": ("ingest_seconds",),
    "graph_p95_ms": ("graph", "p95_ms"),
    "findings_p95_ms": ("findings", "p95_ms"),
    "api_peak_rss_mb": ("api_peak_rss_mb",),
}


def _dig(document: dict[str, Any], path: tuple[str, ...]) -> Any:
    value: Any = document
    for key in path:
        value = value.get(key) if isinstance(value, dict) else None
    return value


def extract(directory: Path) -> dict[str, float]:
    """Flatten the lower-is-better metrics that regression budgets cover."""
    metrics: dict[str, float] = {}
    for path in sorted(directory.glob("**/*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            continue
        if not isinstance(document, dict) or "lane" not in document:
            continue
        prefix = f"{document['lane']}/{document['variant']}"
        measured = document.get("measurements") or {}
        for estate, values in (measured.get("estates") or {}).items():
            if values.get("ingest_status") != "stored":
                continue
            for name, keys in _ESTATE_METRICS.items():
                value = _dig(values, keys)
                if isinstance(value, (int, float)):
                    metrics[f"{prefix}/{estate}/{name}"] = float(value)
        scale = measured.get("scale") or {}
        if scale.get("reached_target"):
            metrics[f"{prefix}/scale/elapsed_seconds"] = float(scale["elapsed_seconds"])
            metrics[f"{prefix}/scale/findings_p95_ms"] = float(scale["steps"][-1]["findings_read"]["p95_ms"])
        if document["lane"] == "accuracy":
            for name in ("duration_seconds", "peak_rss_mb"):
                if isinstance(measured.get(name), (int, float)):
                    metrics[f"{prefix}/{name}"] = float(measured[name])
    return metrics


def compare(baseline: dict[str, Any], measured: dict[str, float]) -> tuple[list[dict[str, float | str]], list[str]]:
    """Return metrics beyond ``baseline * tolerance`` and baseline metrics that were not measured."""
    tolerance = float(baseline["tolerance"])
    regressions: list[dict[str, float | str]] = []
    missing: list[str] = []
    for metric, base_value in sorted(baseline["metrics"].items()):
        if metric not in measured:
            missing.append(metric)
        elif measured[metric] > float(base_value) * tolerance:
            regressions.append(
                {"metric": metric, "baseline": base_value, "measured": measured[metric], "limit": round(float(base_value) * tolerance, 3)}
            )
    return regressions, missing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--results", type=Path, default=RESULTS_DIR)
    parser.add_argument("--baseline", type=Path, default=BASELINE_PATH)
    parser.add_argument("--write", action="store_true", help="Print the measured metrics as baseline JSON instead of comparing")
    args = parser.parse_args()
    measured = extract(args.results)
    if args.write:
        print(json.dumps({"metrics": measured}, indent=2, sort_keys=True))
        return 0
    if not args.baseline.is_file():
        print(f"No baseline at {args.baseline}; recording only.")
        return 0
    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    regressions, missing = compare(baseline, measured)
    lines = ["", "### Regression budget", "", f"Tolerance {baseline['tolerance']}x of {baseline.get('source', 'baseline')}."]
    lines += [f"- REGRESSION {row['metric']}: {row['measured']} > limit {row['limit']} (baseline {row['baseline']})" for row in regressions]
    lines += [f"- not measured this run: {metric}" for metric in missing]
    if not regressions:
        lines.append(f"- {len(baseline['metrics']) - len(missing)} metrics within budget")
    text = "\n".join(lines) + "\n"
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(text)
    return 1 if regressions else 0


if __name__ == "__main__":
    raise SystemExit(main())
