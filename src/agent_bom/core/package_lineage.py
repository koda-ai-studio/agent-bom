"""Resolve recorded package parents within one observed inventory.

One rule for every surface that draws package lineage (CycloneDX, SPDX and the
unified graph): a parent links only when it names exactly one distinct
identity in the same ecosystem and inventory.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from agent_bom.core.packages import normalize_package_ecosystem, normalize_package_name


@dataclass(frozen=True, slots=True)
class DependencyRecord:
    """The recorded lineage fields of one package in one inventory."""

    stable_id: str
    name: str
    ecosystem: str
    is_direct: bool
    parent_package: str | None
    version_evidence: tuple[Mapping[str, Any], ...] = ()


def resolve_dependency_edges(records: Sequence[DependencyRecord]) -> tuple[list[tuple[str, str]], set[str]]:
    """Return canonical parent/child IDs and unresolved transitive IDs.

    Parent names carry no version constraint. Link only one distinct matching
    identity in the same ecosystem and inventory; never pick an arbitrary
    version or borrow a package from another agent/environment. Duplicate
    observations of the same canonical package are not ambiguous.
    """
    candidates: dict[tuple[str, str], set[str]] = defaultdict(set)
    for record in records:
        ecosystem = normalize_package_ecosystem(record.ecosystem)
        candidates[ecosystem, normalize_package_name(record.name, ecosystem)].add(record.stable_id)
    edges: set[tuple[str, str]] = set()
    unresolved: set[str] = set()
    inventory_ids = {record.stable_id for record in records}
    for record in records:
        declared = [
            e.get("parent_stable_ids")
            for e in record.version_evidence
            if isinstance(e, Mapping) and e.get("type") in {"sbom", "lockfile"} and "parent_stable_ids" in e
        ]
        if declared:
            parents = {ref for refs in declared if isinstance(refs, list) for ref in refs if isinstance(ref, str)}
            edges.update((ref, record.stable_id) for ref in parents & inventory_ids if ref != record.stable_id)
            if parents - inventory_ids or (not parents and not record.is_direct):
                unresolved.add(record.stable_id)
            continue
        if record.is_direct:
            continue
        ecosystem = normalize_package_ecosystem(record.ecosystem)
        parents = candidates.get((ecosystem, normalize_package_name(record.parent_package or "", ecosystem)), set())
        if len(parents) != 1 or record.stable_id in parents:
            unresolved.add(record.stable_id)
        else:
            edges.add((next(iter(parents)), record.stable_id))
    return sorted(edges), unresolved
