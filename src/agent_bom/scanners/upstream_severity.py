"""Give distro fix advisories the severity and intel of the CVEs they fix.

OSV publishes distro fix advisories (Debian DLA/DSA, Ubuntu USN, AlmaLinux
ALSA, Red Hat RHSA, ...) without a severity of their own; the record only links
the upstream CVEs it fixes. Left ``unknown``, such a finding trips the
fail-closed policy gate even when every upstream CVE is scored.

For each unknown-severity advisory with linked CVEs, the severity becomes the
maximum of those CVEs (CVSS score first, then the advisory label), read from
records the scan already holds, then the local vulnerability DB, then bounded
OSV lookups (:mod:`agent_bom.scanners.linked_cve_lookup`). A CVE the Debian
tracker marks fixed in the installed version, or not affected in a release it
still tracks, does not count. EPSS and KEV attach through the same CVEs from the
local DB. An advisory with no usable rating stays ``unknown``, the finding says
why, and a gap in the data keeps failing closed.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from agent_bom.advisory_ids import derive_cve_from_advisory_id, upstream_advisory_ids
from agent_bom.core.distro_eol import end_of_life_release
from agent_bom.core.severity import severity_basis, severity_rank
from agent_bom.core.versions.ordering import compare_version_order
from agent_bom.coverage import record_scan_note
from agent_bom.db import schema as db_schema
from agent_bom.exploitability import parse_cvss_vector_signals
from agent_bom.http_client import request_with_retry
from agent_bom.models import Package, Severity, Vulnerability
from agent_bom.package_utils import normalize_package_name
from agent_bom.scanners.advisory_merge import advisory_keys
from agent_bom.scanners.enrichment_apply import apply_epss_entry, apply_kev_entry
from agent_bom.scanners.linked_cve_lookup import (
    GAP_BUDGET,
    GAP_OFFLINE,
    GAP_RATE_LIMITED,
    LinkedCveLookup,
    LinkedCveQuery,
    LinkedCveRecord,
    RequestFn,
    lookup_linked_cves,
    valid_cve_id,
    valid_distro_cve_id,
)
from agent_bom.scanners.risk import cvss_to_severity, parse_cvss_vector, severity_from_label
from agent_bom.scanners.state import _bump_scan_perf, record_scan_warning
from agent_bom.vuln_compliance import tag_vulnerability

_logger = logging.getLogger(__name__)
_SQLITE_CHUNK = 400
_DISTRO_ECOSYSTEMS = frozenset({"deb", "apk", "rpm"})
_NOTE_CVE_LIMIT = 5
_GAP_TEXT = {
    GAP_OFFLINE: "the scan is offline",
    GAP_RATE_LIMITED: "OSV applied a rate limit",
    GAP_BUDGET: "the lookup budget ran out",
}


@dataclass(frozen=True)
class _Score:
    cve_id: str
    severity: Severity
    cvss_score: float | None
    cvss_vector: str | None

    def rank(self) -> tuple[float, int]:
        """Higher CVSS score first, then the worse advisory label."""
        return (self.cvss_score if self.cvss_score is not None else -1.0, severity_rank(self.severity.value))


def _score(cve_id: str, label: object, cvss_score: float | None, cvss_vector: str | None) -> _Score | None:
    if cvss_score is None and isinstance(cvss_vector, str) and cvss_vector:
        cvss_score = parse_cvss_vector(cvss_vector)
    severity = cvss_to_severity(cvss_score) if cvss_score is not None else severity_from_label(label if isinstance(label, str) else None)
    if severity in (Severity.UNKNOWN, Severity.NONE):
        return None
    return _Score(cve_id, severity, cvss_score, cvss_vector or None)


def _is_distro_package(pkg: Package) -> bool:
    return (pkg.ecosystem or "").lower() in _DISTRO_ECOSYSTEMS


def _upstream_cves(vuln: Vulnerability) -> list[str]:
    return [item for item in upstream_advisory_ids(vuln.upstream_ids) if item.upper().startswith("CVE-")]


def _linked_cves(pkg: Package, vuln: Vulnerability) -> list[str]:
    """The CVEs that rate this advisory; a distro CVE record with no links rates itself."""
    linked = _upstream_cves(vuln)
    if linked or not _is_distro_package(pkg):
        return linked
    return sorted({cve for value in [vuln.id, *vuln.aliases] if (cve := derive_cve_from_advisory_id(value))})


def _scan_index(packages: Iterable[Package]) -> dict[str, _Score]:
    index: dict[str, _Score] = {}
    for pkg in packages:
        for vuln in pkg.vulnerabilities:
            if severity_basis(vuln.severity_source) == "default":
                continue
            for key in advisory_keys(vuln):
                if not key.upper().startswith("CVE-"):
                    continue
                score = _score(key, vuln.severity.value, vuln.cvss_score, vuln.cvss_vector)
                if score is not None and (key not in index or score.rank() > index[key].rank()):
                    index[key] = score
    return index


@dataclass
class _LocalIntel:
    scores: dict[str, _Score]
    epss: dict[str, dict]
    kev: dict[str, dict]
    tracker_fixes: dict[tuple[str, str, str], str] = field(default_factory=dict)


def _read_local_tracker_fixes(conn: sqlite3.Connection, intel: _LocalIntel, cve_ids: list[str]) -> None:
    """Read Debian tracker rows; an older database without the table simply has none."""
    try:
        for offset in range(0, len(cve_ids), _SQLITE_CHUNK):
            chunk = [f"DEBIAN-{cve}" for cve in cve_ids[offset : offset + _SQLITE_CHUNK]]
            marks = ",".join("?" for _ in chunk)
            for vuln_id, ecosystem, package_name, fixed in conn.execute(
                f"SELECT vuln_id, ecosystem, package_name, fixed FROM affected WHERE vuln_id IN ({marks})",  # nosec B608 -- generated placeholders only; values are bound.
                chunk,
            ):
                if fixed:
                    intel.tracker_fixes[(vuln_id.removeprefix("DEBIAN-"), package_name, ecosystem)] = fixed
    except sqlite3.Error as exc:
        _logger.debug("Local Debian tracker rows unavailable: %s", exc)


def _read_local_intel(db_path: Path, cve_ids: list[str]) -> _LocalIntel:
    intel = _LocalIntel({}, {}, {})
    if not cve_ids or not db_path.is_file():
        return intel
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        _logger.debug("Local vulnerability DB unavailable for upstream severity: %s", exc)
        return intel
    try:
        for offset in range(0, len(cve_ids), _SQLITE_CHUNK):
            chunk = cve_ids[offset : offset + _SQLITE_CHUNK]
            marks = ",".join("?" for _ in chunk)
            for cve_id, label, cvss_score, cvss_vector in conn.execute(
                f"SELECT id, severity, cvss_score, cvss_vector FROM vulns WHERE id IN ({marks})",  # nosec B608 -- generated placeholders only; values are bound.
                chunk,
            ):
                score = _score(cve_id, label, cvss_score, cvss_vector)
                if score is not None:
                    intel.scores[cve_id] = score
            for cve_id, probability, percentile in conn.execute(
                f"SELECT cve_id, probability, percentile FROM epss_scores WHERE cve_id IN ({marks})",  # nosec B608 -- generated placeholders only; values are bound.
                chunk,
            ):
                intel.epss[cve_id] = {"score": probability, "percentile": percentile}
            for cve_id, date_added, due_date in conn.execute(
                f"SELECT cve_id, date_added, due_date FROM kev_entries WHERE cve_id IN ({marks})",  # nosec B608 -- generated placeholders only; values are bound.
                chunk,
            ):
                intel.kev[cve_id] = {"date_added": date_added, "due_date": due_date}
    except sqlite3.Error as exc:
        _logger.debug("Local vulnerability DB read failed for upstream severity: %s", exc)
    else:
        _read_local_tracker_fixes(conn, intel, cve_ids)
    finally:
        conn.close()
    return intel


def _apply_score(vuln: Vulnerability, pkg: Package, best: _Score) -> None:
    vuln.severity = best.severity
    vuln.cvss_score = best.cvss_score
    vuln.cvss_vector = best.cvss_vector
    vuln.severity_source = f"upstream_cve:{best.cve_id}"
    signals = parse_cvss_vector_signals(best.cvss_vector)
    vuln.attack_vector = signals.attack_vector
    vuln.attack_complexity = signals.attack_complexity
    vuln.privileges_required = signals.privileges_required
    vuln.user_interaction = signals.user_interaction
    vuln.network_exploitable = bool(signals.network_exploitable)
    vuln.compliance_tags = tag_vulnerability(vuln, pkg)


def _debian_release(pkg: Package) -> str | None:
    """Major release of a Debian package, or ``None`` when the scan does not know it."""
    if (pkg.ecosystem or "").lower() != "deb" or (pkg.distro_name or "").strip().lower() != "debian":
        return None
    major = (pkg.distro_version or "").strip().split(".")[0]
    return major if major.isdigit() else None


@dataclass
class _Evidence:
    """Everything known about the linked CVEs when resolving one scan's advisories."""

    index: dict[str, _Score]
    local: _LocalIntel
    records: dict[str, LinkedCveRecord]
    unanswered: set[str]
    tracked_releases: set[str]

    def score(self, cve: str) -> _Score | None:
        found = self.index.get(cve) or self.local.scores.get(cve)
        if found is not None:
            return found
        record = self.records.get(cve)
        return _score(cve, record.label, record.cvss_score, record.cvss_vector) if record is not None else None

    def release_is_tracked(self, release: str) -> bool:
        return release in self.tracked_releases or end_of_life_release(f"debian:{release}") is None


def _tracked_releases(records: Iterable[LinkedCveRecord]) -> set[str]:
    """Debian releases the tracker feed still lists, seen in the records fetched for this scan."""
    return {
        ecosystem.removeprefix("Debian:")
        for record in records
        for (_, ecosystem) in record.tracker or {}
        if ecosystem.startswith("Debian:")
    }


def _tracker_clears(evidence: _Evidence, pkg: Package, cve: str) -> bool:
    """Whether the Debian tracker says this CVE does not affect this package as installed.

    Omission counts only for a source package the record lists under another
    release, and only in a release the feed still tracks: an end-of-life release
    leaves the feed, and a CVE filed under a different source package says nothing
    about this one.
    """
    release = _debian_release(pkg)
    if release is None:
        return False
    source = normalize_package_name(pkg.source_package or pkg.name, "deb")
    fixed = evidence.local.tracker_fixes.get((cve, source, f"debian:{release}"))
    record = evidence.records.get(cve)
    if fixed is None and record is not None and record.tracker is not None:
        entries = {(normalize_package_name(name, "deb"), ecosystem): value for (name, ecosystem), value in record.tracker.items()}
        if (source, f"Debian:{release}") not in entries:
            return any(name == source for name, _ in entries) and evidence.release_is_tracked(release)
        fixed = entries[(source, f"Debian:{release}")]
    if not fixed:
        return False
    order = compare_version_order(pkg.version, fixed, "deb")
    return order is not None and order >= 0


def _shorten(cves: list[str]) -> str:
    shown = ", ".join(cves[:_NOTE_CVE_LIMIT])
    return f"{shown} and {len(cves) - _NOTE_CVE_LIMIT} more" if len(cves) > _NOTE_CVE_LIMIT else shown


def _resolution_note(total: int, excluded: list[str], unanswered: list[str]) -> str | None:
    parts: list[str] = []
    if unanswered:
        considered = total - len(unanswered)
        parts.append(
            f"Based on {considered} of {total} linked CVEs; {_shorten(unanswered)} could not be looked up, so this may be understated."
        )
    if len(excluded) == total:
        parts.append("The Debian tracker marks every linked CVE fixed or not affected for this package and release.")
    elif excluded:
        parts.append(
            f"The Debian tracker marks {_shorten(excluded)} fixed or not affected for this package and release, so they do not count."
        )
    return " ".join(parts) or None


@dataclass
class _Tally:
    missing: set[str] = field(default_factory=set)
    understated: set[str] = field(default_factory=set)
    cleared: set[str] = field(default_factory=set)
    no_links: set[str] = field(default_factory=set)


def _needs_rating(pkg: Package, vuln: Vulnerability) -> bool:
    """Unknown severity, or a distro record holding only a namespace default."""
    return vuln.severity == Severity.UNKNOWN or (_is_distro_package(pkg) and severity_basis(vuln.severity_source) == "default")


def _resolve_one(pkg: Package, vuln: Vulnerability, cves: list[str], evidence: _Evidence, tally: _Tally) -> bool:
    excluded = [cve for cve in cves if _tracker_clears(evidence, pkg, cve)]
    counted = [cve for cve in cves if cve not in excluded]
    unanswered = [cve for cve in counted if cve in evidence.unanswered and evidence.score(cve) is None]
    # Sorted first so equal ranks resolve to the lowest CVE id on every run.
    candidates = [score for cve in sorted(counted) if (score := evidence.score(cve)) is not None]
    if vuln.severity != Severity.UNKNOWN and not candidates:
        return False
    if candidates:
        _apply_score(vuln, pkg, max(candidates, key=_Score.rank))
    vuln.severity_note = _resolution_note(len(cves), excluded, unanswered)
    if candidates and unanswered:
        tally.understated.add(vuln.id)
    elif not candidates and counted:
        tally.missing.add(vuln.id)
    elif not candidates:
        tally.cleared.add(vuln.id)
    return bool(candidates)


def _report_gaps(tally: _Tally, lookup: LinkedCveLookup | None) -> None:
    reason = _GAP_TEXT.get(lookup.gap_reason, "linked CVE lookups failed") if lookup and lookup.gap_reason else None
    if tally.missing:
        if reason:
            detail = f"their linked CVEs could not be rated because {reason}"
        elif lookup:
            detail = "their upstream CVEs have no rating in this scan, the local database or OSV"
        else:
            detail = "their upstream CVEs have no rating in this scan or local database"
        record_scan_warning(
            f"Severity is missing for {len(tally.missing)} distro advisories: {detail}. "
            "These findings remain unknown, not low risk. Run `agent-bom db update` to populate local severity data."
        )
    if tally.understated:
        record_scan_warning(
            f"Severity of {len(tally.understated)} distro advisories may be understated: "
            f"some of their linked CVEs were not looked up because {reason or 'linked CVE lookups failed'}."
        )
    if tally.no_links:
        record_scan_note(
            ecosystem="distro",
            path="advisories-without-cve",
            reason="distro_advisory_without_cve",
            detail=f"{len(tally.no_links)} distro advisories link no CVE (often data updates such as tzdata), so they stay unrated.",
            replace=True,
        )
    if tally.cleared:
        record_scan_note(
            ecosystem="distro",
            path="advisories-cleared-by-tracker",
            reason="distro_advisory_cleared_by_tracker",
            detail=f"{len(tally.cleared)} distro advisories stay unrated: the Debian tracker marks every linked CVE fixed or not affected.",
            replace=True,
        )


def _apply_resolution(packages: list[Package], local: _LocalIntel, lookup: LinkedCveLookup | None) -> int:
    records = lookup.records if lookup else {}
    evidence = _Evidence(_scan_index(packages), local, records, lookup.unanswered if lookup else set(), _tracked_releases(records.values()))
    tally = _Tally()
    resolved = 0
    for pkg in packages:
        for vuln in pkg.vulnerabilities:
            cves = _linked_cves(pkg, vuln)
            if vuln.epss_score is None:
                apply_epss_entry(vuln, cves, local.epss)
            if not vuln.is_kev:
                apply_kev_entry(vuln, cves, local.kev)
            if not _needs_rating(pkg, vuln):
                continue
            if cves:
                resolved += _resolve_one(pkg, vuln, cves, evidence, tally)
            elif _is_distro_package(pkg):
                vuln.severity_note = "This advisory links no CVE, so it has no rating to inherit."
                tally.no_links.add(vuln.id)
    _report_gaps(tally, lookup)
    return resolved


def _wanted_cves(packages: list[Package]) -> list[str]:
    return sorted({cve for pkg in packages for vuln in pkg.vulnerabilities for cve in _linked_cves(pkg, vuln)})


def resolve_upstream_advisory_severity(packages: list[Package], *, db_path: Path | None = None) -> int:
    """Resolve unknown advisory severities from data already on this machine; return how many changed."""
    return _apply_resolution(packages, _read_local_intel(db_path or db_schema.DB_PATH, _wanted_cves(packages)), None)


def _lookup_queries(packages: list[Package], local: _LocalIntel) -> list[LinkedCveQuery]:
    """One query per CVE still needed, each advisory's first CVE ahead of any advisory's second.

    The request budget then reaches every advisory before it deepens any rollup.
    """
    index = _scan_index(packages)
    rank: dict[str, tuple[int, str | None]] = {}
    for pkg in packages:
        if not _is_distro_package(pkg):
            continue
        for vuln in pkg.vulnerabilities:
            if not _needs_rating(pkg, vuln):
                continue
            scoped_links = {value.upper() for value in upstream_advisory_ids(vuln.upstream_ids) if valid_distro_cve_id(value.upper())}
            for position, raw in enumerate(_linked_cves(pkg, vuln)):
                cve = raw.upper()
                if not valid_cve_id(cve) or cve in index or cve in local.scores:
                    continue
                scoped = next((link for link in scoped_links if link.endswith(f"-{cve}")), None)
                if scoped is None and (pkg.ecosystem or "").lower() == "deb" and _debian_release(pkg) is not None:
                    scoped = f"DEBIAN-{cve}"
                held = rank.get(cve)
                rank[cve] = (min(position, held[0]) if held else position, scoped or (held[1] if held else None))
    return [LinkedCveQuery(cve, rank[cve][1]) for cve in sorted(rank, key=lambda cve: (rank[cve][0], cve))]


async def resolve_distro_advisory_severity(
    packages: list[Package],
    *,
    offline: bool,
    db_path: Path | None = None,
    request_fn: RequestFn = request_with_retry,
) -> int:
    """Resolve unknown advisory severities, looking up linked CVEs the machine does not hold."""
    local = _read_local_intel(db_path or db_schema.DB_PATH, _wanted_cves(packages))
    lookup = await lookup_linked_cves(_lookup_queries(packages, local), offline=offline, request_fn=request_fn)
    _bump_scan_perf("linked_cve_lookups", lookup.requests)
    _bump_scan_perf("linked_cve_cache_hits", lookup.cache_hits)
    return _apply_resolution(packages, local, lookup)
