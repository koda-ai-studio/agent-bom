"""The demo graph speaks the same data model as a live scan.

One id scheme per kind, one package -> CVE edge pair, package dependency
edges, images distinct from workloads, and recorded hosting edges.
"""

from __future__ import annotations

from collections import Counter

import pytest

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import EntityType


class _CapturingStore:
    def __init__(self) -> None:
        self.graphs: list[UnifiedGraph] = []

    def list_snapshots(self, tenant_id: str) -> list[dict]:
        return []

    def save_graph(self, graph: UnifiedGraph) -> None:
        self.graphs.append(graph)


@pytest.fixture(scope="module")
def demo_graph() -> UnifiedGraph:
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_SCAN_ID, SHOWCASE_TENANT, seed_showcase_graph_if_empty

    store = _CapturingStore()
    seed_showcase_graph_if_empty(store, tenant_id=SHOWCASE_TENANT)
    return next(graph for graph in store.graphs if graph.scan_id == SHOWCASE_SCAN_ID)


def _aliases(graph: UnifiedGraph) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for node in graph.nodes.values():
        identity = node.attributes.get("identity")
        for alias in (identity or {}).get("aliases") or [] if isinstance(identity, dict) else []:
            mapping[alias] = node.id
    return mapping


@pytest.mark.parametrize(
    ("entity_type", "prefix"),
    [(EntityType.PACKAGE, "pkg:"), (EntityType.ORG, "org:"), (EntityType.MISCONFIGURATION, "misconfig:")],
)
def test_one_id_scheme_per_kind(demo_graph: UnifiedGraph, entity_type: EntityType, prefix: str) -> None:
    ids = [node.id for node in demo_graph.nodes.values() if node.entity_type == entity_type]
    assert ids
    styles = Counter(node_id.split(":", 1)[0] + ":" for node_id in ids)
    assert set(styles) == {prefix}, styles


@pytest.mark.parametrize(
    "legacy_id",
    ["organization:northstar-health-ai", "mc:pii-public", "mc:sg-open"],
)
def test_retired_ids_stay_resolvable_as_aliases(demo_graph: UnifiedGraph, legacy_id: str) -> None:
    aliases = _aliases(demo_graph)
    assert legacy_id in aliases, legacy_id
    assert aliases[legacy_id] in demo_graph.nodes


def test_retired_package_occurrence_ids_alias_to_canonical_packages(demo_graph: UnifiedGraph) -> None:
    aliases = _aliases(demo_graph)
    retired = {alias: target for alias, target in aliases.items() if alias.startswith("package:")}
    assert len(retired) >= 700, len(retired)
    for alias, target in retired.items():
        assert target.startswith("pkg:"), (alias, target)
        assert demo_graph.nodes[target].entity_type == EntityType.PACKAGE


def test_report_finding_node_ids_resolve_in_the_graph(demo_graph: UnifiedGraph) -> None:
    from agent_bom.demo_estate.bootstrap import _run_demo_scan_report
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

    findings = _run_demo_scan_report(tenant_id=SHOWCASE_TENANT)["findings"]
    referenced = {str(row[key]) for row in findings for key in ("node_id", "finding_node_id") if row.get(key)}
    assert len(referenced) > 1000
    missing = sorted(node_id for node_id in referenced if node_id not in demo_graph.nodes)
    assert not missing, missing[:5]
    package_rows = [
        row for row in findings if row.get("cve_id") and (row.get("asset") or {}).get("asset_type") in {"package", "mcp_server"}
    ]
    assert len(package_rows) > 700
    assert all(str(row.get("node_id") or "").startswith("pkg:") for row in package_rows)
