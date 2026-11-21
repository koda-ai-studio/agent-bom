"""Write the product-proof roll-up fixture from the real backend roll-up.

The capture and E2E mocks serve ``/v1/graph/rollup`` and
``/v1/graph/node-aggregates`` from this file, so every badge count in a demo
screenshot is the number the API computes for the same graph, never a
hand-written one.

Usage: python scripts/generate_product_proof_rollup.py [--check]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.rollup import node_aggregate, rollup_view
from agent_bom.graph.semantic_layer import semantic_layer

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "ui"
OUTPUT = UI / "tests" / "fixtures" / "product-proof-rollup.json"
_EXPORT = 'import("./scripts/product-proof-graph.mjs").then((m) => process.stdout.write(JSON.stringify(m.buildGraph())))'


def demo_graph() -> dict[str, Any]:
    node = shutil.which("node")
    if node is None:
        raise SystemExit("node is required to read ui/scripts/product-proof-graph.mjs")
    result = subprocess.run([node, "-e", _EXPORT], cwd=UI, capture_output=True, text=True, check=True)  # noqa: S603
    return json.loads(result.stdout)


def build_fixture(data: dict[str, Any]) -> dict[str, Any]:
    graph = UnifiedGraph.from_dict(data)
    aggregates = {}
    for node_id in sorted(graph.nodes):
        aggregate = node_aggregate(graph, node_id)
        assert aggregate is not None
        aggregates[node_id] = {"semantic_layer": semantic_layer(graph.nodes[node_id]), "aggregate": aggregate.to_dict()}
    return {"rollup": rollup_view(graph), "node_aggregates": aggregates}


def render(fixture: dict[str, Any]) -> str:
    return json.dumps(fixture, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail when the committed fixture is stale")
    args = parser.parse_args(argv)
    text = render(build_fixture(demo_graph()))
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != text:
            print(f"{OUTPUT.relative_to(ROOT)} is stale; run python scripts/generate_product_proof_rollup.py", file=sys.stderr)
            return 1
        return 0
    OUTPUT.write_text(text)
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
