"""Comparison and alias normalization for the real-repository accuracy measurement.

Advisory identity comes from OSV alias data only (GHSA, CVE, PYSEC, GO, RUSTSEC
and so on joined transitively), never from agent-bom's own alias claims, so a
wrong alias in the tool cannot turn a miss into a match.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

PackageKey = tuple[str, str, str]

FINDING_ID_FIELDS = ("vulnerability_id", "cve_id")
FINDING_ID_LIST_FIELDS = ("advisory_ids", "advisory_aliases", "cve_ids")

# Miss reasons: "withdrawn", "published_after_db_sync" and "modified_after_db_sync"
# are data-timing differences; "package_not_found" is an inventory miss judged
# against the scan's coverage warnings; "unexplained" is a matcher miss.


def package_key(ecosystem: str, name: str, version: str) -> PackageKey:
    if ecosystem == "PyPI":
        name = re.sub(r"[-_.]+", "-", name).lower()
    elif ecosystem == "npm":
        name = name.lower()
    if ecosystem == "Go":
        version = version.removeprefix("v")
    return ecosystem, name, version


def label(key: PackageKey) -> str:
    return f"{key[1]}@{key[2]}"


def finding_ids(finding: Mapping[str, Any]) -> set[str]:
    ids = {str(finding[f]).upper() for f in FINDING_ID_FIELDS if finding.get(f)}
    for list_field in FINDING_ID_LIST_FIELDS:
        ids.update(str(value).upper() for value in finding.get(list_field) or [] if value)
    return ids


def build_alias_groups(records: Mapping[str, Mapping[str, Any] | None]) -> dict[str, str]:
    """Map every ID and alias to one representative ID of its connected alias group."""
    parent: dict[str, str] = {}

    def find(node: str) -> str:
        parent.setdefault(node, node)
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    for key, record in records.items():
        if not record:
            continue
        root = find(str(record.get("id", key)).upper())
        for alias in record.get("aliases") or []:
            other = find(str(alias).upper())
            if other != root:
                parent[max(root, other)] = min(root, other)
                root = min(root, other)
    return {node: find(node) for node in list(parent)}


def compare_packages(expected: set[PackageKey], found: set[PackageKey]) -> dict[str, Any]:
    def fmt(keys: Iterable[PackageKey]) -> list[str]:
        return sorted(f"{k[0]}:{label(k)}" for k in keys)

    return {
        "expected": len(expected),
        "found": len(expected & found),
        "missing": fmt(expected - found),
        "unexpected": fmt(found - expected),
    }


@dataclass
class AdvisoryContext:
    records: Mapping[str, Mapping[str, Any] | None]
    found_packages: set[PackageKey]
    db_synced_at: str


@dataclass
class AdvisoryComparison:
    expected: int = 0
    matched: int = 0
    missed: list[dict[str, Any]] = field(default_factory=list)
    extra: list[dict[str, Any]] = field(default_factory=list)

    @property
    def unexplained_missed(self) -> int:
        return sum(1 for m in self.missed if m["reason"] == "unexplained")

    @property
    def false_positive_candidates(self) -> int:
        return sum(1 for e in self.extra if e["reason"] == "osv_does_not_list_version")


def _timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _known(ids: Iterable[str], ctx: AdvisoryContext) -> list[Mapping[str, Any]]:
    return [record for i in sorted(ids) if (record := ctx.records.get(i))]


def _after_sync(records: list[Mapping[str, Any]], key: str, ctx: AdvisoryContext) -> bool:
    synced = _timestamp(ctx.db_synced_at)
    return synced is not None and any((t := _timestamp(r.get(key))) and t > synced for r in records)


def classify_miss(key: PackageKey, ids: set[str], ctx: AdvisoryContext) -> str:
    records = _known(ids, ctx)
    if records and all(r.get("withdrawn") for r in records):
        return "withdrawn"
    if key not in ctx.found_packages:
        return "package_not_found"
    if _after_sync(records, "published", ctx):
        return "published_after_db_sync"
    if _after_sync(records, "modified", ctx):
        return "modified_after_db_sync"
    return "unexplained"


def classify_extra(ids: set[str], ctx: AdvisoryContext) -> str:
    records = _known(ids, ctx)
    if not records:
        return "not_in_osv"
    if any(r.get("withdrawn") for r in records):
        return "withdrawn_in_osv"
    if _after_sync(records, "modified", ctx):
        return "modified_after_db_sync"
    return "osv_does_not_list_version"


def _expected_groups(ids: set[str], groups: Mapping[str, str]) -> dict[str, set[str]]:
    by_group: dict[str, set[str]] = {}
    for advisory in ids:
        by_group.setdefault(groups.get(advisory.upper(), advisory.upper()), set()).add(advisory.upper())
    return by_group


def _compare_package(
    key: PackageKey,
    expected_ids: set[str],
    findings: list[set[str]],
    groups: Mapping[str, str],
    ctx: AdvisoryContext,
    out: AdvisoryComparison,
) -> None:
    wanted = _expected_groups(expected_ids, groups)
    hit: set[str] = set()
    extras: dict[frozenset[str], set[str]] = {}
    for ids in findings:
        finding_groups = {groups.get(i.upper(), i.upper()) for i in ids}
        overlap = finding_groups & wanted.keys()
        hit |= overlap
        if not overlap:
            extras.setdefault(frozenset(finding_groups), set()).update(i.upper() for i in ids)
    out.expected += len(wanted)
    out.matched += len(hit)
    for group in sorted(wanted.keys() - hit):
        reason = classify_miss(key, wanted[group], ctx)
        out.missed.append({"ecosystem": key[0], "package": label(key), "ids": sorted(wanted[group]), "reason": reason})
    for ids in extras.values():
        reason = classify_extra(ids, ctx)
        out.extra.append({"ecosystem": key[0], "package": label(key), "ids": sorted(ids), "reason": reason})


def compare_advisories(
    expected: Mapping[PackageKey, set[str]],
    found: Mapping[PackageKey, list[set[str]]],
    ctx: AdvisoryContext,
) -> AdvisoryComparison:
    """Compare per package; an expected alias group counts once however many findings hit it.

    ``expected`` holds every parsed package, including those with no advisory,
    so a finding on a clean package is reported as extra. Findings on packages
    outside ``expected`` are not judged here: those packages were not in an
    independently parsed lockfile.
    """
    groups = build_alias_groups(ctx.records)
    result = AdvisoryComparison()
    for key in sorted(expected):
        _compare_package(key, expected[key], found.get(key, []), groups, ctx, result)
    return result
