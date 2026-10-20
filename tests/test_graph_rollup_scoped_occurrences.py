"""A roll-up scope counts only the finding occurrences its own assets hold.

The graph keeps one node per advisory (``vuln:<CVE>``) and one per failed
benchmark check, shared by every asset that holds it; ``finding_ids_by_asset``
records which asset holds which occurrence. A scope that contains one holder
must count that holder's occurrences, not every occurrence of the advisory
across the estate, so disjoint top-level scopes sum to the estate total.
Suppressed occurrences (an approved exception) are not open and count nowhere.
"""

from __future__ import annotations

import pytest

from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.rollup import drill_down, rollup_view
from agent_bom.graph.types import EntityType, RelationshipType

pytestmark = pytest.mark.graph_contract("warn")

_CVE = "CVE-2020-14343"


def _edge(graph: UnifiedGraph, source: str, target: str, rel: RelationshipType) -> None:
    graph.add_edge(UnifiedEdge(source=source, target=target, relationship=rel))


def _estate() -> UnifiedGraph:
    """Two orgs; each holds pyyaml@5.3 in its own image and one failed IMDS check on its own instance."""
    g = UnifiedGraph(scan_id="scoped", tenant_id="default")
    by_asset_vuln: dict[str, list[str]] = {}
    by_asset_check: dict[str, list[str]] = {}
    for org in ("a", "b"):
        g.add_node(UnifiedNode(id=f"org:{org}", entity_type=EntityType.ORG, label=org))
        g.add_node(UnifiedNode(id=f"account:{org}", entity_type=EntityType.ACCOUNT, label=org))
        _edge(g, f"org:{org}", f"account:{org}", RelationshipType.CONTAINS)
        server, package, instance = f"server:{org}", f"pkg:pypi:pyyaml@5.3:image:{org}", f"cloud_resource:i-{org}"
        g.add_node(UnifiedNode(id=server, entity_type=EntityType.SERVER, label=server))
        g.add_node(
            UnifiedNode(id=package, entity_type=EntityType.PACKAGE, label="pyyaml@5.3", attributes={"version": "5.3", "ecosystem": "pypi"})
        )
        g.add_node(UnifiedNode(id=instance, entity_type=EntityType.CLOUD_RESOURCE, label=instance))
        _edge(g, f"account:{org}", server, RelationshipType.CONTAINS)
        _edge(g, f"account:{org}", instance, RelationshipType.OWNS)
        _edge(g, server, package, RelationshipType.DEPENDS_ON)
        _edge(g, package, f"vuln:{_CVE}", RelationshipType.VULNERABLE_TO)
        # The instance holds its failed check only by ``vulnerable_to``, no CONTAINS.
        _edge(g, instance, f"misconfig:imds-{org}", RelationshipType.VULNERABLE_TO)
        g.add_node(
            UnifiedNode(
                id=f"misconfig:imds-{org}",
                entity_type=EntityType.MISCONFIGURATION,
                label="IMDSv1 enabled",
                severity="medium",
                attributes={"finding_id": f"imds-{org}", "finding_ids_by_asset": {instance: [f"imds-{org}"]}},
            )
        )
        by_asset_vuln[package] = [f"vuln-{org}"]
        by_asset_check[server] = [f"check-{org}"]
    g.add_node(
        UnifiedNode(
            id=f"vuln:{_CVE}",
            entity_type=EntityType.VULNERABILITY,
            label=_CVE,
            severity="critical",
            attributes={"vulnerability_id": _CVE, "finding_ids_by_asset": by_asset_vuln},
        )
    )
    g.add_node(
        UnifiedNode(
            id="misconfig:shared-check",
            entity_type=EntityType.MISCONFIGURATION,
            label="tool without auth",
            severity="high",
            attributes={"finding_ids_by_asset": by_asset_check},
        )
    )
    for org in ("a", "b"):
        _edge(g, f"server:{org}", "misconfig:shared-check", RelationshipType.VULNERABLE_TO)
    return g


def _top(view: dict, node_id: str) -> dict:
    return next(entry for entry in view["top_level"] if entry["id"] == node_id)["aggregate"]


def test_each_org_counts_only_the_occurrences_its_assets_hold() -> None:
    view = rollup_view(_estate())
    for org in ("a", "b"):
        agg = _top(view, f"org:{org}")
        assert agg["finding_occurrence_count"] == 3, (org, agg)
        assert agg["issue_count"] == 3, (org, agg)
    summary = view["summary"]
    assert summary["finding_occurrence_count"] == 6
    # One advisory on one package is one issue estate-wide; the checks are per occurrence.
    assert summary["issue_count"] == 5
    assert sum(entry["aggregate"]["finding_occurrence_count"] for entry in view["top_level"]) == 6


def test_a_check_held_only_by_vulnerable_to_rolls_up_under_its_instance() -> None:
    view = rollup_view(_estate())
    top_ids = {entry["id"] for entry in view["top_level"]}
    assert not {nid for nid in top_ids if nid.startswith("misconfig:")}, top_ids
    drilled = drill_down(_estate(), "account:a")
    instance = next(child for child in drilled["children"] if child["id"] == "cloud_resource:i-a")
    assert instance["aggregate"]["issue_count"] == 1
    assert instance["aggregate"]["finding_occurrence_count"] == 1


def test_a_drill_down_counts_its_own_holders_only() -> None:
    drilled = drill_down(_estate(), "org:a")
    account = next(child for child in drilled["children"] if child["id"] == "account:a")
    assert account["aggregate"]["finding_occurrence_count"] == 3
    assert account["aggregate"]["issue_count"] == 3


def test_suppressed_occurrences_count_nowhere() -> None:
    view = rollup_view(_estate(), suppressed_finding_ids=frozenset({"vuln-a"}))
    assert _top(view, "org:a")["finding_occurrence_count"] == 2
    assert _top(view, "org:a")["issue_count"] == 2
    assert _top(view, "org:b")["finding_occurrence_count"] == 3
    assert view["summary"]["finding_occurrence_count"] == 5
    # vuln-b still holds the same advisory on the same package: the issue stays open.
    assert view["summary"]["issue_count"] == 5

    both = rollup_view(_estate(), suppressed_finding_ids=frozenset({"vuln-a", "vuln-b", "imds-a"}))
    assert both["summary"]["finding_occurrence_count"] == 3
    assert both["summary"]["issue_count"] == 3
    assert both["summary"]["issue_severity_counts"]["critical"] == 0
