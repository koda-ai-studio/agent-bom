"""Exact equivalence helpers for the workflow harness: projections, diffs and the update/delete mutation."""

from __future__ import annotations

import copy

from scripts.generate_graph_benchmark_estate import generate_estate
from scripts.perf.workflow_equivalence import (
    EQUIVALENCE_FIELDS,
    finding_projections,
    lifecycle_mismatches,
    mutate_inventory,
    projection_mismatches,
)
from scripts.perf.workflow_profiles import expected_findings, inventory_from_estate


def _row(**overrides: object) -> dict:
    row = {
        "vulnerability_id": "CVE-2026-000001",
        "package_name": "left-pad",
        "package_version": "1.0.0",
        "canonical_id": "c1",
        "package_stable_id": "p1",
        "ecosystem": "npm",
        "primary_advisory_source": "osv",
        "advisory_sources": ["osv"],
        "severity_source": "cvss",
        "affected_agents": ["b", "a"],
        "affected_servers": ["s1"],
        "affected_agent_ids": ["id-b", "id-a"],
        "published_at": "2026-09-01T00:00:00Z",
        "modified_at": "2026-10-01T00:00:00Z",
        "advisory_coverage_state": "complete",
        "asset": {"kind": "package", "name": "left-pad"},
    }
    row.update(overrides)
    return row


def test_fields_cover_identity_source_time_scope_and_coverage() -> None:
    assert set(EQUIVALENCE_FIELDS) == {"identity", "source", "time", "scope", "coverage"}
    assert "canonical_id" in EQUIVALENCE_FIELDS["identity"]
    assert "affected_agents" in EQUIVALENCE_FIELDS["scope"]


def test_projection_ignores_list_order_and_unrelated_fields() -> None:
    first = finding_projections([_row()])
    second = finding_projections([_row(affected_agents=["a", "b"], affected_agent_ids=["id-a", "id-b"], risk_score=9.1)])
    assert first == second
    assert list(first) == [("CVE-2026-000001", "left-pad", "1.0.0")]


def test_projection_digest_is_order_independent_and_field_sensitive() -> None:
    from scripts.perf.workflow_equivalence import projection_digest

    rows = [_row(), _row(vulnerability_id="CVE-2026-000002")]
    assert projection_digest(rows) == projection_digest(list(reversed(rows)))
    assert projection_digest(rows) != projection_digest([_row(advisory_coverage_state="partial"), rows[1]])


def test_mismatches_name_the_finding_and_the_field() -> None:
    before = finding_projections([_row(), _row(vulnerability_id="CVE-2026-000002")])
    after = finding_projections([_row(affected_servers=["s1", "s2"]), _row(vulnerability_id="CVE-2026-000003")])
    assert projection_mismatches(before, after) == [
        "changed CVE-2026-000001|left-pad|1.0.0 scope.affected_servers",
        "missing CVE-2026-000002|left-pad|1.0.0",
        "unexpected CVE-2026-000003|left-pad|1.0.0",
    ]
    assert projection_mismatches(before, before) == []


def test_lifecycle_requires_stable_ids_and_first_seen_and_monotonic_last_seen() -> None:
    before = {("v", "p", "1"): {"finding_id": "f1", "first_seen": "2026-11-01T00:00:00Z", "last_seen": "2026-11-01T00:00:00Z"}}
    later = {("v", "p", "1"): {"finding_id": "f1", "first_seen": "2026-11-01T00:00:00Z", "last_seen": "2026-11-02T00:00:00Z"}}
    assert lifecycle_mismatches(before, later) == []
    moved = copy.deepcopy(later)
    moved[("v", "p", "1")].update(first_seen="2026-11-02T00:00:00Z", finding_id="f2")
    assert lifecycle_mismatches(before, moved) == [
        "v|p|1 finding_id f1 -> f2",
        "v|p|1 first_seen 2026-11-01T00:00:00Z -> 2026-11-02T00:00:00Z",
    ]
    regressed = {("v", "p", "1"): {"finding_id": "f1", "first_seen": "2026-11-01T00:00:00Z", "last_seen": "2026-10-01T00:00:00Z"}}
    assert lifecycle_mismatches(before, regressed) == ["v|p|1 last_seen went backwards"]


def test_mutation_deletes_one_finding_and_widens_the_scope_of_another() -> None:
    report, _summary = generate_estate(agents=12, seed=2145, vulnerable_package_rate=0.08)
    inventory = inventory_from_estate(report)
    original = copy.deepcopy(inventory)
    mutated, change = mutate_inventory(report, inventory)

    assert inventory == original, "the input inventory must not be modified"
    before = expected_findings(report, inventory)
    after = expected_findings(report, mutated)
    assert after == before - {change["deleted"]}
    assert change["deleted"] in before and change["widened"] in after
    agents_with = [
        agent["name"]
        for agent in mutated["agents"]
        for server in agent["mcp_servers"]
        for package in server["packages"]
        if (package["name"], package["version"]) == change["widened"][1:]
    ]
    assert change["added_agent"] in agents_with
    assert mutate_inventory(report, inventory) == (mutated, change), "the mutation is deterministic"
