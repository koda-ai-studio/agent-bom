"""Node.js core runtime findings from the Node.js security working group index.

Node.js core has no OSV ecosystem, so an installed ``node`` runtime (the
``generic`` component image and host scans report from ``NODE_VERSION`` and
``/usr/local/bin/node``) is matched here by exact release against the index's
``vulnerable`` and ``patched`` ranges. A runtime is affected when its release
is in ``vulnerable`` and not in ``patched``. The fixed version is the lowest
unaffected release the index names on the same major line; a line the index
gives no fix for (often an end-of-life line) carries none rather than a
cross-major upgrade.

Advisories scoped only to Windows (``affectedEnvironments: ["win32"]``) are not
applied, because detection reads POSIX install paths. A failed or stale lookup
records a ``runtime_advisory_coverage_unknown`` gap, never a clean result. The
index stops listing a line after its end-of-life date, so a line past it (as of
the data's date) keeps its findings and adds a ``runtime_end_of_life`` coverage
warning: the assessment is real but cannot be complete.
"""

from __future__ import annotations

import asyncio
from typing import Any

from agent_bom.core.severity import severity_from_label
from agent_bom.models import Package, Vulnerability
from agent_bom.scanners import nodejs_advisory_data as data
from agent_bom.scanners.local_advisories import merge_scanner_vulnerabilities
from agent_bom.scanners.nodejs_semver import Version, parse_version, range_bounds, satisfies
from agent_bom.scanners.state import record_coverage_warning
from agent_bom.security import sanitize_error
from agent_bom.vuln_compliance import tag_vulnerability

ADVISORY_SOURCE = "nodejs_security_wg"
RUNTIME_END_OF_LIFE = "runtime_end_of_life"
_ENTRY_URL = data.REPOSITORY + "/blob/main/vuln/core/{key}.json"
_RECEIPT = "runtime_advisory_lookup"


def is_nodejs_runtime(package: Package) -> bool:
    return getattr(package, "ecosystem", None) == "generic" and getattr(package, "name", None) == "node"


def _affected(version: Version, entry: dict[str, Any]) -> bool:
    return satisfies(version, entry["vulnerable"]) and not satisfies(version, entry["patched"])


def _fixed_version(version: Version, entry: dict[str, Any]) -> str | None:
    """Lowest release on the installed major line that the index says is not affected."""
    candidates = {floor for floor, _ in range_bounds(entry["patched"]) if floor} | {
        ceiling for _, ceiling in range_bounds(entry["vulnerable"]) if ceiling
    }
    eligible = sorted(c for c in candidates if c[0] == version[0] and c > version and not _affected(c, entry))
    return ".".join(map(str, eligible[0])) if eligible else None


def _applies_to_posix(entry: dict[str, Any]) -> bool:
    environments = {str(item).lower() for item in entry["affectedEnvironments"]}
    return environments != {"win32"}


def _summary(entry: dict[str, Any], identifier: str) -> str:
    text = str(entry.get("description") or "").strip() or str(entry.get("overview") or "").strip().split("\n\n", 1)[0]
    return (text or f"Node.js core vulnerability {identifier}")[:200]


def _findings_for_entry(key: str, entry: dict[str, Any], version: Version) -> list[Vulnerability]:
    fixed = _fixed_version(version, entry)
    references = [ref for ref in (entry.get("ref"), _ENTRY_URL.format(key=key)) if isinstance(ref, str) and ref.startswith("https://")]
    cvss = entry.get("cvss_score")
    identifiers = entry["cve"] or [f"NSWG-COR-{key}"]
    return [
        Vulnerability(
            id=identifier,
            summary=_summary(entry, identifier),
            severity=severity_from_label(entry.get("severity")),
            severity_source=ADVISORY_SOURCE,
            cvss_score=float(cvss) if isinstance(cvss, (int, float)) and not isinstance(cvss, bool) else None,
            fixed_version=fixed,
            references=references,
            advisory_sources=[ADVISORY_SOURCE],
        )
        for identifier in identifiers
    ]


def matching_findings(entries: dict[str, dict[str, Any]], package: Package) -> list[Vulnerability]:
    """Findings for the installed release; raises ``ValueError`` when the release is not a plain version."""
    version = parse_version(package.version)
    findings: dict[str, Vulnerability] = {}
    for key, entry in sorted(entries.items(), key=lambda item: int(item[0])):
        if not _applies_to_posix(entry) or not _affected(version, entry):
            continue
        for finding in _findings_for_entry(key, entry, version):
            findings.setdefault(finding.id, finding)
    return list(findings.values())


def _record_gap(package: Package, reason: str) -> None:
    record_coverage_warning(
        {
            "ecosystem": "generic",
            "release": f"node:{package.version}",
            "reason": "runtime_advisory_coverage_unknown",
            "package_count": 1,
            "advisory_rows": 0,
            "detail": (
                f"Node.js runtime advisory coverage for node {package.version} is unknown: {reason}. "
                "Run `agent-bom db update` (source nodejs) or scan online; zero findings here are not a clean result."
            ),
        }
    )


def release_line(version: Version) -> str:
    """Release line as the Node.js release schedule names it: ``24``, or ``0.10`` before 4.x."""
    return str(version[0]) if version[0] else f"0.{version[1]}"


def _end_of_life_detail(version: Version, index: data.CoreIndex) -> str | None:
    """Why the index cannot be complete for this release line, or ``None`` while the line is supported."""
    line = release_line(version)
    end = index.end_of_life.get(line)
    as_of = index.fetched_at.date().isoformat()
    if end is None:
        return (
            f"Node.js {line}.x is not in the Node.js release schedule as of {as_of}, so whether the "
            "Node.js security working group lists vulnerabilities for it is unknown"
        )
    if end > as_of:
        return None
    return (
        f"Node.js {line}.x reached end-of-life on {end}; the Node.js security working group no longer lists "
        "vulnerabilities for it, so advisories published after that date are missing. Upgrade to a supported release line"
    )


def _record_end_of_life(package: Package, detail: str, findings: int) -> None:
    record_coverage_warning(
        {
            "ecosystem": "generic",
            "release": f"node:{package.version}",
            "reason": RUNTIME_END_OF_LIFE,
            "package_count": 1,
            "advisory_rows": findings,
            "detail": detail,
        }
    )


def _receipt(index: data.CoreIndex, count: int) -> dict[str, Any]:
    return {
        "type": _RECEIPT,
        "url": data.INDEX_URL,
        "repository_url": data.REPOSITORY,
        "status": index.origin,
        "checked_at": index.fetched_at.isoformat(),
        "sha256": index.sha256,
        "advisory_count": count,
        "assessment": "upstream_release_lookup_complete",
        "boundary": "Exact-release match against the Node.js security working group core index as of checked_at.",
    }


async def scan_nodejs_runtimes(packages: list[Package], *, offline: bool) -> int:
    """Attach index findings to each Node.js runtime; any failure is an explicit coverage gap."""
    if not packages:
        return 0
    try:
        index: data.CoreIndex | None = await asyncio.to_thread(data.select_index, offline=offline)
        failure = ""
    except ValueError as exc:
        index, failure = None, sanitize_error(exc, max_length=240)
    total = 0
    for package in packages:
        package.version_evidence = [item for item in package.version_evidence if item.get("type") != _RECEIPT]
        if index is None:
            _record_gap(package, failure)
            continue
        try:
            findings = matching_findings(index.entries, package)
        except ValueError:
            _record_gap(package, "the installed release is not a plain MAJOR.MINOR.PATCH version")
            continue
        for finding in findings:
            finding.compliance_tags = tag_vulnerability(finding, package)
        total += len(merge_scanner_vulnerabilities(package, findings))
        package.version_evidence.append(_receipt(index, len(findings)))
        if detail := _end_of_life_detail(parse_version(package.version), index):
            _record_end_of_life(package, detail, len(findings))
    return total
