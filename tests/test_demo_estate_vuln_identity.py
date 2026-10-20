"""One vulnerability node per advisory in the demo estate, as the product contract mints it.

The live builder and ``finding_row_node_id`` name a CVE ``vuln:<CVE>``; the
estate used to mint one ``vuln:demo-estate:<finding-id>`` node per occurrence,
so one advisory had 55 nodes and REST impact and MCP blast radius disagreed on
it. Occurrence truth (which package, which finding, whether it applies) now
lives on the occurrence edge, the way ``graph.blast_projection`` records it.
"""

from __future__ import annotations

from collections import defaultdict

import pytest

from agent_bom.demo_estate.enterprise_composition import build_demo_estate
from agent_bom.demo_estate.enterprise_correlation import build_estate_correlations
from agent_bom.demo_estate.enterprise_findings import build_estate_findings
from agent_bom.demo_estate.estate_graph import project_estate_into_graph
from agent_bom.evidence.finding_node_ids import finding_row_node_id
from agent_bom.graph.applicability import edge_applicability
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import EntityType, RelationshipType

_RETIRED_PREFIX = "vuln:demo-estate:"


@pytest.fixture(scope="module")
def estate_findings():
    estate = build_demo_estate(tenant_id="default")
    return estate, build_estate_findings(estate)


@pytest.fixture(scope="module")
def projected(estate_findings):
    estate, findings = estate_findings
    graph = UnifiedGraph(scan_id="estate-vuln-identity", tenant_id="default")
    project_estate_into_graph(graph, estate, findings=findings, correlations=build_estate_correlations(estate))
    return graph


@pytest.fixture(scope="module")
def showcase_snapshot():
    from agent_bom.demo_estate import showcase_graph as sg

    identities = sg.build_demo_identity_store("default")
    graph, identity_store, drift_store = sg.build_showcase_graph(
        tenant_id="default", scan_id="showcase", profile="current", identity_store=identities
    )
    sg.apply_showcase_overlays(graph, tenant_id="default", identity_store=identity_store, drift_store=drift_store)
    sg.finalize_showcase_snapshot(graph, profile="current")
    sg.project_estate_onto_showcase(graph, tenant_id="default", profile="current")
    sg._materialize_showcase_attack_paths(graph)
    return graph


def _cve_findings(findings):
    return [f for f in findings if f.finding_type.value == "CVE"]


def test_no_per_occurrence_vulnerability_ids_remain(projected, showcase_snapshot) -> None:
    for graph in (projected, showcase_snapshot):
        assert not [node_id for node_id in graph.nodes if node_id.startswith(_RETIRED_PREFIX)]


def test_one_vulnerability_node_per_advisory(projected, estate_findings) -> None:
    _, findings = estate_findings
    advisories = {f.vulnerability_id for f in _cve_findings(findings)}
    assert len(advisories) > 1
    vulns = {node_id for node_id, node in projected.nodes.items() if node.entity_type is EntityType.VULNERABILITY}
    assert vulns == {f"vuln:{advisory}" for advisory in advisories}
    assert len(_cve_findings(findings)) > len(vulns), "occurrences must outnumber advisories for this to mean anything"


def test_estate_finding_ids_follow_the_product_contract(estate_findings) -> None:
    _, findings = estate_findings
    for finding in _cve_findings(findings):
        assert finding.finding_node_id == f"vuln:{finding.vulnerability_id}"
        assert finding.finding_node_id == finding_row_node_id(finding.to_dict())


def test_every_finding_resolves_to_its_own_occurrence(projected, estate_findings) -> None:
    _, findings = estate_findings
    edges = {(e.source, e.target, e.relationship): e for e in projected.edges}
    for finding in findings:
        assert finding.node_id in projected.nodes and finding.finding_node_id in projected.nodes
        if finding.finding_type.value != "CVE":
            continue
        node = projected.nodes[finding.finding_node_id]
        assert finding.id in node.attributes["finding_ids_by_asset"][finding.node_id]
        occurrence = edges[(finding.node_id, finding.finding_node_id, RelationshipType.VULNERABLE_TO)]
        assert occurrence.evidence["finding_ids"] == [finding.id]
        assert isinstance(occurrence.evidence.get("applicability"), dict)
        assert (finding.finding_node_id, finding.node_id, RelationshipType.AFFECTS) in edges


def test_retired_occurrence_ids_are_recorded_as_aliases(projected, estate_findings) -> None:
    _, findings = estate_findings
    for finding in _cve_findings(findings):
        aliases = projected.nodes[finding.finding_node_id].attributes["identity"]["aliases"]
        assert f"{_RETIRED_PREFIX}{finding.id}" in aliases


def test_retired_occurrence_ids_resolve_through_the_store(tmp_path, projected, estate_findings) -> None:
    from agent_bom.api.graph_store import SQLiteGraphStore

    _, findings = estate_findings
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(projected)
    sample = _cve_findings(findings)[:5]
    resolved = store.resolve_node_aliases(tenant_id="default", node_ids=[f"{_RETIRED_PREFIX}{f.id}" for f in sample])
    assert resolved == {f"{_RETIRED_PREFIX}{f.id}": f.finding_node_id for f in sample}


def test_impact_on_a_cve_is_the_union_of_its_occurrences(showcase_snapshot) -> None:
    graph = showcase_snapshot
    vuln_id = "vuln:CVE-2020-14343"
    holders = sorted({e.source for e in graph.edges if e.target == vuln_id and e.relationship is RelationshipType.VULNERABLE_TO})
    assert len(holders) > 2, "the local and the estate occurrences must share the advisory node"
    expected: set[str] = set()
    for holder in holders:
        expected.add(holder)
        expected.update(graph.impact_of(holder, max_depth=12)["affected_nodes"])
    expected.discard(vuln_id)
    affected = set(graph.impact_of(vuln_id, max_depth=13)["affected_nodes"])
    assert affected == expected


def test_shared_advisory_never_lends_the_local_verdict_to_estate_occurrences(showcase_snapshot) -> None:
    graph = showcase_snapshot
    vuln = graph.nodes["vuln:CVE-2020-14343"]
    verdicts: dict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        if edge.target == vuln.id and edge.relationship is RelationshipType.VULNERABLE_TO and not edge.evidence.get("derived_via"):
            source = "estate" if "image:" in edge.source else "local"
            verdicts[source].add(edge_applicability(edge, vuln.attributes).verdict)
    assert verdicts["local"] == {"likely"}
    assert verdicts["estate"] == {"unknown"}


def test_estate_paths_carry_only_their_own_occurrence(showcase_snapshot, estate_findings) -> None:
    _, findings = estate_findings
    by_id = {f.id: f for f in _cve_findings(findings)}
    checked = 0
    for path in showcase_snapshot.attack_paths:
        estate_ids = [fid for fid in path.finding_ids if fid in by_id]
        if not estate_ids:
            continue
        assert len(estate_ids) == 1, path.finding_ids
        assert by_id[estate_ids[0]].node_id in path.hops
        checked += 1
    assert checked > 0


def test_every_estate_occurrence_keeps_its_own_materialized_path(showcase_snapshot, estate_findings) -> None:
    """Occurrences that share an advisory node and an entry must not collapse onto one path."""
    _, findings = estate_findings
    on_paths = {fid for path in showcase_snapshot.attack_paths for fid in path.finding_ids}
    missing = [f.id for f in _cve_findings(findings) if f.id not in on_paths]
    assert not missing, f"{len(missing)} estate CVE occurrences lost their path"
