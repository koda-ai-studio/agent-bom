"""Every showcase advisory names the finding behind each of its occurrences.

The demo's curated scan records one finding per hand-built occurrence (for
example ``pkg:pypi:pyyaml@5.3`` -> ``vuln:CVE-2020-14343``), but the seeded graph
only mapped the estate's image-scoped holders, so the hero occurrence of every
advisory carried no finding id and its attack path could not open the finding.
The seed now links the curated report onto the current snapshot with the same
linker a live scan's persist path uses.
"""

from __future__ import annotations

import json

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.demo_estate import bootstrap
from agent_bom.demo_estate.showcase_constants import SHOWCASE_SCAN_ID
from agent_bom.demo_estate.showcase_graph import seed_showcase_graph_if_empty
from agent_bom.graph.types import EntityType, RelationshipType


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    report = bootstrap._run_demo_scan_report(tenant_id="default")
    pristine = json.dumps(report, sort_keys=True, default=str)
    store = SQLiteGraphStore(tmp_path_factory.mktemp("advisory-ids") / "graph.db")
    assert seed_showcase_graph_if_empty(store, tenant_id="default", scan_report=lambda: report)
    graph = store.load_graph(tenant_id="default", scan_id=SHOWCASE_SCAN_ID)
    return graph, report, pristine


def test_every_advisory_occurrence_names_a_recorded_finding(seeded) -> None:
    graph, report, _ = seeded
    finding_ids = {str(row.get("id")) for row in report["findings"]}
    advisories = [node for node in graph.nodes.values() if node.entity_type is EntityType.VULNERABILITY]
    assert advisories
    for advisory in advisories:
        mapping = advisory.attributes.get("finding_ids_by_asset") or {}
        holders = {
            edge.source for edge in graph.edges if edge.target == advisory.id and edge.relationship is RelationshipType.VULNERABLE_TO
        }
        assert holders <= set(mapping), (advisory.id, sorted(holders - set(mapping))[:3])
        assert {fid for ids in mapping.values() for fid in ids} <= finding_ids


def test_the_hero_occurrence_carries_its_curated_finding(seeded) -> None:
    graph, report, _ = seeded
    hero = next(
        row["id"]
        for row in report["findings"]
        if row.get("node_id") == "pkg:pypi:pyyaml@5.3" and row.get("finding_node_id") == "vuln:CVE-2020-14343"
    )
    assert hero in graph.nodes["vuln:CVE-2020-14343"].attributes["finding_ids_by_asset"]["pkg:pypi:pyyaml@5.3"]


def test_linking_leaves_the_scan_report_untouched(seeded) -> None:
    _, report, pristine = seeded
    assert json.dumps(report, sort_keys=True, default=str) == pristine
