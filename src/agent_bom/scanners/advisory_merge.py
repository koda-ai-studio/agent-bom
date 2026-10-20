"""Deterministic reconciliation of advisory aliases across scanner sources."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import asdict

from agent_bom.advisory_ids import derive_cve_from_advisory_id
from agent_bom.core.severity import severity_basis, severity_rank
from agent_bom.models import Vulnerability
from agent_bom.scanners.state import record_scan_warning

_FUSED_ALIAS_WARNING = (
    "Some local advisories list aliases for several distinct CVEs (a stale upstream alias group); "
    "they were matched by their own IDs only. Run `agent-bom db update` to refresh them."
)


def self_consistent_aliases(advisory_id: str, aliases: list[str]) -> list[str]:
    """Return a stored record's aliases, or none when they name several distinct CVEs.

    One advisory has one CVE. A stored alias set naming two (an alias group
    fused upstream and kept by a stale DB) would chain unrelated advisories
    together, so the record is identified by its own ID alone.
    """
    cves = {cve for value in [advisory_id, *aliases] if (cve := derive_cve_from_advisory_id(value))}
    if len(cves) <= 1:
        return list(aliases)
    record_scan_warning(_FUSED_ALIAS_WARNING)
    return []


def _primary_cve(vuln: Vulnerability) -> str | None:
    return vuln.id.strip().upper() if vuln.id.strip().upper().startswith("CVE-") else None


def advisory_keys(vuln: Vulnerability) -> set[str]:
    keys = {value.strip() for value in [vuln.id, *vuln.aliases] if value.strip()}
    return keys | {cve for key in keys if (cve := derive_cve_from_advisory_id(key))}


def _external_only(vuln: Vulnerability) -> bool:
    return bool(vuln.advisory_sources) and all(source.startswith("external") for source in vuln.advisory_sources)


def _advisory_origin(vuln: Vulnerability) -> str:
    # Merged aliases are sorted, so they cannot identify the winning source.
    if vuln.severity_source and vuln.severity_source.startswith("advisory:"):
        return vuln.severity_source.removeprefix("advisory:")
    if not vuln.id.upper().startswith("CVE-"):
        return vuln.id
    # The input canonicalizer retains the original advisory as the first alias.
    return next((alias for alias in vuln.aliases if not alias.upper().startswith("CVE-")), vuln.id)


def _alias_clusters(records: list[Vulnerability]) -> list[list[Vulnerability]]:
    """Group records sharing an advisory key, in first-seen order.

    A cluster never holds two different primary CVEs: a shared alias is not
    evidence that two separately-identified CVEs are the same advisory.
    """
    parents = list(range(len(records)))
    primaries: dict[int, set[str]] = {index: {cve} if (cve := _primary_cve(record)) else set() for index, record in enumerate(records)}

    def root(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left, right = root(left), root(right)
        if left == right or (primaries[left] and primaries[right] and primaries[left] != primaries[right]):
            return
        parents[left] = right
        primaries[right] |= primaries[left]

    owners: dict[str, int] = {}
    for index, record in enumerate(records):
        for key in sorted(advisory_keys(record)):
            if key in owners:
                union(index, owners[key])
            else:
                owners[key] = index
    groups: dict[int, list[Vulnerability]] = {}
    for index, record in enumerate(records):
        groups.setdefault(root(index), []).append(record)
    return list(groups.values())


# Release-scoped OS ecosystems: an empty fix authoritatively means "no fix for
# this release", so a sibling record's fix (often another branch) never fills it.
_RELEASE_SCOPED_ECOSYSTEMS = frozenset({"deb", "apk", "rpm"})


def fix_fallback_allowed(package: object) -> bool:
    """Whether a cluster may fill a missing fix from a sibling record for ``package``."""
    return str(getattr(package, "ecosystem", "") or "").lower() not in _RELEASE_SCOPED_ECOSYSTEMS


def _rank(record: Vulnerability) -> tuple:
    return (
        # A namespace default is not a rating; any scored or rated record outranks it.
        severity_basis(record.severity_source) == "default",
        -severity_rank(record.severity),
        -(record.cvss_score if record.cvss_score is not None else -1),
        _advisory_origin(record),
        json.dumps(asdict(record), sort_keys=True, default=str),
    )


def merge_advisory_clusters(records: list[Vulnerability], *, fix_fallback: bool = False) -> list[Vulnerability]:
    """Collapse transitive aliases; retain the highest authoritative severity.

    Advisory DB evidence supersedes an external-only report. Within that tier,
    a scored or rated record beats a namespace default, then severity, score, original advisory ID and serialized content break ties in
    that order. Score and vector always come from the same representative. The
    fix does too, unless the representative has none and ``fix_fallback`` is
    set: then the highest-ranked authoritative record carrying a fix supplies
    it (one call's records all describe one package, so no other package's
    range can contribute). Provenance, references and affected symbols retain
    the whole cluster.
    """
    merged: list[Vulnerability] = []
    for cluster in _alias_clusters(records):
        authoritative = sorted((record for record in cluster if not _external_only(record)), key=_rank) or sorted(cluster, key=_rank)
        representative = authoritative[0]
        result = deepcopy(representative)
        if fix_fallback and not (result.fixed_version or "").strip():
            result.fixed_version = next((record.fixed_version for record in authoritative if (record.fixed_version or "").strip()), None)
        keys = set().union(*(advisory_keys(record) for record in cluster))
        cves = sorted(key for key in keys if key.upper().startswith("CVE-"))
        result.id = cves[0] if cves else min(keys)
        result.aliases = sorted(keys - {result.id})
        if (len(cluster) > 1 or result.id != representative.id) and severity_basis(representative.severity_source) != "default":
            result.severity_source = f"advisory:{_advisory_origin(representative)}"
        for field in ("advisory_sources", "references", "cwe_ids", "affected_symbols", "upstream_ids"):
            setattr(result, field, sorted({value for record in cluster for value in getattr(record, field)}))
        paths = {path for record in cluster for path in record.affected_symbols_by_path}
        result.affected_symbols_by_path = {
            path: sorted({symbol for record in cluster for symbol in record.affected_symbols_by_path.get(path, [])})
            for path in sorted(paths)
        }
        epss_records = [record for record in cluster if record.epss_score is not None]
        if epss_records:
            epss_record = min(epss_records, key=lambda record: (-(record.epss_score or 0), record.epss_cve_id or record.id))
            for field in ("epss_score", "epss_percentile", "epss_cve_id", "exploitability"):
                setattr(result, field, getattr(epss_record, field))
        kev_records = [record for record in cluster if record.is_kev]
        result.is_kev = bool(kev_records)
        if kev_records:
            kev_record = min(kev_records, key=lambda record: (record.kev_due_date or "9999", record.kev_cve_id or record.id))
            for field in ("kev_date_added", "kev_due_date", "kev_cve_id"):
                setattr(result, field, getattr(kev_record, field))
        merged.append(result)
    return sorted(merged, key=lambda record: record.id)
