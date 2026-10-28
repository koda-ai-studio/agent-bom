"""One policy for local advisory rows whose range receipt cannot verify a match.

A row tiered ``unverified_range`` (legacy import without range limits, or a
range the stored bounds cannot evaluate) says "this advisory names the
package", not "this version is affected". ``check`` and ``scan`` apply the
same rules:

* a live OSV answer for the package decides: rows OSV confirms are replaced by
  the live record, rows it does not confirm are dropped with a scan note;
* without a live answer the row is reported as a ``possibly_affected``
  candidate — visible on every surface, never a vulnerability, never a fix
  claim, never a severity-gate trigger;
* a fix is never borrowed for such a row, whichever path merged it.
"""

from __future__ import annotations

from typing import Any

from agent_bom.advisory_ids import MATCH_CONFIDENCE_UNVERIFIED_RANGE, STALE_RECEIPT_WARNINGS
from agent_bom.coverage import record_scan_note
from agent_bom.models import Package, Vulnerability
from agent_bom.scanners.advisory_merge import advisory_keys
from agent_bom.scanners.state import consume_coverage_warnings, consume_scan_warnings, restore_scan_warnings

UNVERIFIED_LOCAL_RANGE = "unverified_local_range"
_REFRESH_HINT = "run `agent-bom db update` to restore range bounds, then rescan"


def is_unverified(vuln: Vulnerability) -> bool:
    return vuln.match_confidence_tier == MATCH_CONFIDENCE_UNVERIFIED_RANGE


def withhold_unverified_fixes(vulns: list[Vulnerability]) -> None:
    """Shared ``check``/``scan`` rule: an unverified row never carries a fix recommendation."""
    for vuln in vulns:
        if is_unverified(vuln):
            vuln.fixed_version = None


def unverified_packages(packages: list[Package]) -> list[Package]:
    return [pkg for pkg in packages if any(is_unverified(v) for v in pkg.vulnerabilities)]


def supersede_with_live_answer(pkg: Package, live_vulns: list[Vulnerability]) -> list[str]:
    """Drop every unverified row once live OSV has answered for ``pkg``; return the ids OSV did not confirm."""
    live_keys = set().union(*(advisory_keys(v) for v in live_vulns)) if live_vulns else set()
    unconfirmed = [v.id for v in pkg.vulnerabilities if is_unverified(v) and not (advisory_keys(v) & live_keys)]
    pkg.vulnerabilities = [v for v in pkg.vulnerabilities if not is_unverified(v)]
    if unconfirmed:
        record_scan_note(
            ecosystem=pkg.ecosystem.lower(),
            path=f"{pkg.name}@{pkg.version}",
            reason="stale_local_rows_superseded",
            detail=(
                f"{pkg.name}@{pkg.version}: live OSV did not confirm {', '.join(sorted(unconfirmed))} "
                "(stale local advisory rows without range receipts); the live answer wins. "
                "Run `agent-bom db update` to refresh the local advisory DB."
            ),
        )
    return sorted(unconfirmed)


def _candidate(pkg: Package, vuln: Vulnerability) -> dict[str, Any]:
    return {
        "id": vuln.id,
        "verdict": "possibly_affected",
        "reason": UNVERIFIED_LOCAL_RANGE,
        "detail": (
            f"local advisory row for {pkg.name} {pkg.version} has no range receipt, so the installed version "
            f"cannot be confirmed affected and no fix is claimed; {_REFRESH_HINT}"
        ),
        "severity": str(getattr(vuln.severity, "value", vuln.severity) or "unknown").lower(),
        "cvss_score": vuln.cvss_score,
        "summary": vuln.summary,
        "aliases": list(vuln.aliases),
        "source": ",".join(vuln.advisory_sources) or "local-db",
        "match_confidence_tier": MATCH_CONFIDENCE_UNVERIFIED_RANGE,
    }


def demote_to_candidates(pkg: Package) -> int:
    """Move unverified rows no live answer decided into ``pkg.possibly_affected``."""
    candidates = [v for v in pkg.vulnerabilities if is_unverified(v)]
    if not candidates:
        return 0
    recorded = {entry["id"] for entry in pkg.possibly_affected}
    for vuln in candidates:
        if vuln.id not in recorded:
            pkg.possibly_affected.append(_candidate(pkg, vuln))
            recorded.add(vuln.id)
    pkg.vulnerabilities = [v for v in pkg.vulnerabilities if not is_unverified(v)]
    return len(candidates)


def retire_stale_receipt_warnings_if_decided(packages: list[Package]) -> None:
    """Live OSV decided every unverified row: the receipt warning is no longer a coverage gap."""
    undecided = any(entry.get("reason") == UNVERIFIED_LOCAL_RANGE for pkg in packages for entry in pkg.possibly_affected)
    if undecided or unverified_packages(packages):
        return
    warnings = consume_scan_warnings()
    if not any(message in STALE_RECEIPT_WARNINGS for message in warnings):
        restore_scan_warnings(warnings, [])
        return
    coverage = consume_coverage_warnings()
    restore_scan_warnings([message for message in warnings if message not in STALE_RECEIPT_WARNINGS], coverage)
