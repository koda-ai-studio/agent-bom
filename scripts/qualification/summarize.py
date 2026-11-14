#!/usr/bin/env python3
"""Render qualification results as a Markdown table for the step summary."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import RESULTS_DIR  # noqa: E402

_KEY_MEASUREMENTS = (
    "image_mode",
    "packages",
    "unique_advisories",
    "unknown_severity",
    "agents",
    "mcp_servers",
    "credential_findings",
    "grade",
    "outcome",
    "duration_seconds",
    "peak_rss_mb",
)


def load(directory: Path) -> list[dict[str, Any]]:
    documents = []
    for path in sorted(directory.glob("**/*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            continue
        if isinstance(document, dict) and "lane" in document and "checks" in document:
            documents.append(document)
    return documents


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _key_measurements(document: dict[str, Any]) -> str:
    measured = document.get("measurements") or {}
    parts = [f"{key}={measured[key]}" for key in _KEY_MEASUREMENTS if key in measured and measured[key] is not None]
    parts.extend(f"{key}={value}" for key, value in (measured.get("headline") or {}).items())
    return ", ".join(parts)


def render(documents: list[dict[str, Any]]) -> str:
    if not documents:
        return "## Qualification\n\nNo qualification results were written.\n"
    lines = [
        "## Qualification",
        "",
        "| Lane | Variant | Result | Failed checks | Key measurements |",
        "| --- | --- | --- | --- | --- |",
    ]
    for document in documents:
        failed = ", ".join(item["name"] for item in document["checks"] if not item["ok"]) or "-"
        lines.append(
            f"| {document['lane']} | {document['variant']} | {document['status']} "
            f"| {_cell(failed)} | {_cell(_key_measurements(document))} |"
        )
    defects = [(document, defect) for document in documents for defect in document.get("defects") or []]
    if defects:
        lines += ["", "### Product defects", ""]
        lines += [
            f"- **{defect['id']}** ({document['lane']}/{document['variant']}): {defect['summary']}. Reproduce: `{defect['reproduction']}`"
            for document, defect in defects
        ]
    skipped = [(document, item) for document in documents for item in document.get("not_tested") or []]
    if skipped:
        lines += ["", "### Not tested", ""]
        lines += [f"- {item['area']} ({document['lane']}/{document['variant']}): {item['reason']}" for document, item in skipped]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=RESULTS_DIR)
    args = parser.parse_args()
    text = render(load(args.results))
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
