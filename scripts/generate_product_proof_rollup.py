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
from agent_bom.graph.risk_context import derive_node_risk_context
from agent_bom.graph.rollup import rollup_view
from agent_bom.graph.rollup_node import node_aggregate
from agent_bom.graph.semantic_layer import LAYER_BY_ENTITY_TYPE, semantic_layer

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "ui"
OUTPUT = UI / "tests" / "fixtures" / "product-proof-rollup.json"
# The backend legend layer per kind; the demo graph stamps nodes from it, so it is written first.
LAYERS = UI / "tests" / "fixtures" / "product-proof-layers.json"
# Recorded attributes the unit fixtures use, and the risk context the backend stores for each.
RISK_CONTEXT = UI / "tests" / "fixtures" / "risk-context.json"
# Node aggregates for small E2E fixture graphs, keyed "<case>:<node id>"; each case
# copies the nodes and edges of the spec fixture it stands for.
AGGREGATE_CASES_OUTPUT = UI / "tests" / "fixtures" / "node-aggregate-cases.json"


def _case_node(node_id: str, entity_type: str, label: str, severity: str, risk_score: float) -> dict[str, Any]:
    return {
        "id": node_id,
        "entity_type": entity_type,
        "label": label,
        "status": "active",
        "risk_score": risk_score,
        "severity": severity,
        "attributes": {},
        "compliance_tags": [],
        "data_sources": ["scan"],
        "dimensions": {},
    }


AGGREGATE_CASES: dict[str, dict[str, Any]] = {
    # security-graph-cockpit.spec.ts: the form-data package and its advisory.
    "cockpit": {
        "nodes": [
            _case_node("pkg:form-data", "package", "form-data@4.0.0", "critical", 9.6),
            _case_node("cve:form-data", "vulnerability", "CVE-2025-7783", "critical", 9.8),
        ],
        "edges": [
            {
                "id": "pkg:form-data->cve:form-data:vulnerable_to",
                "source": "pkg:form-data",
                "target": "cve:form-data",
                "relationship": "vulnerable_to",
            }
        ],
        "aggregate": ["pkg:form-data"],
    },
}
RISK_CONTEXT_INPUTS: tuple[tuple[str, dict[str, Any]], ...] = (
    ("role", {"is_admin": True}),
    ("server", {"internet_exposed": True}),
    ("server", {"internet_exposed": "unknown"}),
    ("dataset", {"data_sensitivity": "pii"}),
    ("dataset", {"data_sensitivity": "none"}),
    ("agent", {"internet_exposed": "false"}),
    ("data_store", {"cloud_provider": "snowflake", "resource_type": "stage"}),
    ("dataset", {"data_sensitivity": "none", "privilege_level": "read"}),
)
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


def risk_contexts() -> list[dict[str, Any]]:
    """Unit fixtures carry scan ``scan-1`` and no data sources."""
    return [
        {
            "entity_type": entity_type,
            "attributes": attributes,
            "risk_context": derive_node_risk_context(entity_type, attributes, scan_id="scan-1", data_sources=()),
        }
        for entity_type, attributes in RISK_CONTEXT_INPUTS
    ]


def aggregate_cases() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for case, spec in AGGREGATE_CASES.items():
        graph = UnifiedGraph.from_dict({"scan_id": case, "tenant_id": "default", "nodes": spec["nodes"], "edges": spec["edges"]})
        for node_id in spec["aggregate"]:
            aggregate = node_aggregate(graph, node_id)
            assert aggregate is not None
            out[f"{case}:{node_id}"] = {"semantic_layer": semantic_layer(graph.nodes[node_id]), "aggregate": aggregate.to_dict()}
    return out


def render(fixture: dict[str, Any]) -> str:
    return json.dumps(fixture, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail when the committed fixture is stale")
    args = parser.parse_args(argv)
    layers = render(dict(sorted(LAYER_BY_ENTITY_TYPE.items())))
    contexts = render(risk_contexts())
    cases = render(aggregate_cases())
    if not args.check:
        LAYERS.write_text(layers)
        RISK_CONTEXT.write_text(contexts)
        AGGREGATE_CASES_OUTPUT.write_text(cases)
    text = render(build_fixture(demo_graph()))
    if args.check:
        outputs = ((LAYERS, layers), (RISK_CONTEXT, contexts), (AGGREGATE_CASES_OUTPUT, cases), (OUTPUT, text))
        stale = [path for path, body in outputs if not path.exists() or path.read_text() != body]
        for path in stale:
            print(f"{path.relative_to(ROOT)} is stale; run python scripts/generate_product_proof_rollup.py", file=sys.stderr)
        return 1 if stale else 0
    OUTPUT.write_text(text)
    print(f"wrote {LAYERS.relative_to(ROOT)}, {RISK_CONTEXT.relative_to(ROOT)} and {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
