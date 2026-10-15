#!/usr/bin/env python3
"""Generate docs/EXPERIMENTAL.md from the experimental-feature registry.

Usage:
    python scripts/generate_experimental_docs.py            # regenerate
    python scripts/generate_experimental_docs.py --check    # CI drift guard
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_bom.core.experimental import EXPERIMENTAL_ENV, EXPERIMENTAL_FEATURES  # noqa: E402

DOC_FILE = ROOT / "docs" / "EXPERIMENTAL.md"
GENERATOR = "scripts/generate_experimental_docs.py"


def _link(doc: str) -> str:
    target = doc.removeprefix("docs/")
    return f"[{target}]({target})"


def render() -> str:
    lines = [
        "# Experimental features",
        "",
        f"> Generated from `src/agent_bom/core/experimental.py` by `{GENERATOR}`.",
        "> Do not edit by hand; CI fails when this page drifts from the registry.",
        "",
        "Experimental features ship for evaluation. Their contracts, storage, and",
        "output may change without a deprecation window, and they are not covered",
        "by the supported-surface guarantees in the rest of the docs.",
        "",
        "## Enabling flag-gated features",
        "",
        f"Flag-gated features are **off by default**. Enable them with one setting, `{EXPERIMENTAL_ENV}`,",
        "a comma-separated list of feature ids (`all` enables every flag-gated feature):",
        "",
        "```bash",
        f"export {EXPERIMENTAL_ENV}=traces",
        "```",
        "",
        "While a flag-gated feature is disabled, its API routes return `404` with an",
        "enable hint, MCP tools return the same hint, trace collection and the graph",
        "trace overlay do not run, and the dashboard labels the entry *Experimental*.",
        "`agent-bom doctor` and `GET /v1/system/health` (`experimental_features`)",
        "report the live state.",
        "",
        "`POST /v1/traces` (OTLP ingest) stays available for runtime and cost",
        "telemetry; with `traces` disabled it records no trace findings and the graph",
        "does not overlay trace events.",
        "",
        "Features that are not flag-gated keep the opt-in they shipped with and are",
        "listed here so the experimental label is consistent everywhere.",
        "",
        "## Registry",
        "",
        "| Id | Feature | Surfaces | Flag-gated | Enabled by | Docs |",
        "|---|---|---|---|---|---|",
    ]
    for feature in EXPERIMENTAL_FEATURES:
        gated = "yes" if feature.flag_gated else "no"
        enabled_by = f"`{feature.enabled_by}`" if feature.flag_gated else feature.enabled_by
        surfaces = ", ".join(feature.surfaces)
        lines.append(f"| `{feature.id}` | {feature.title} | {surfaces} | {gated} | {enabled_by} | {_link(feature.doc)} |")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Exit 1 when docs/EXPERIMENTAL.md is stale.")
    args = parser.parse_args(argv)
    rendered = render()
    if args.check:
        on_disk = DOC_FILE.read_text(encoding="utf-8") if DOC_FILE.exists() else ""
        if on_disk != rendered:
            print(f"{DOC_FILE.name} is out of date; run `python {GENERATOR}` and commit the diff.", file=sys.stderr)
            return 1
        print(f"{DOC_FILE.name} is current.")
        return 0
    DOC_FILE.write_text(rendered, encoding="utf-8")
    print(f"Wrote {DOC_FILE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
