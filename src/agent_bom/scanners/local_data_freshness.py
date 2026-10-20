"""Vuln-data freshness and completeness evidence for package lookups.

Local advisory hits are only a trustworthy standalone answer while the local
DB is fresh. The rule for "too old" is :func:`agent_bom.vuln_freshness.local_db_outdated`
(the same condition ``agent-bom db freshness`` warns on); this module turns it
into the console line the scanner prints and the structured evidence that
``check`` returns on every surface (CLI JSON, MCP, REST). A freshness probe
that fails is treated as outdated: unknown freshness never earns trust.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from agent_bom import vuln_freshness
from agent_bom.domain.report_payloads import VulnerabilityFreshnessPayload
from agent_bom.scanners.state import peek_scan_performance, record_coverage_warning
from agent_bom.vuln_freshness import VulnDataFreshness, local_data_age_text, local_db_outdated, offline_env

_logger = logging.getLogger(__name__)

_UPDATE_HINT = "Run `agent-bom db update` to refresh it."
_OPT_OUT_HINT = "Pass --allow-stale-db (or set AGENT_BOM_ALLOW_STALE_DB=1) to accept local data as complete."
_INTEGRITY_HINT = "Upgrade agent-bom or run `agent-bom db update`."


@dataclass(frozen=True)
class CheckDataEvidence:
    """What the vulnerability data behind one check was, and whether it was enough."""

    freshness: VulnerabilityFreshnessPayload | None
    status: str
    reason: str
    outdated: bool = False

    @property
    def complete(self) -> bool:
        return self.status == "complete"

    def completeness(self) -> dict[str, str]:
        return {"status": self.status, "reason": self.reason}

    def blocks_clean(self) -> bool:
        """Whether a result with nothing at or above the gate must fail closed as incomplete.

        True when untrusted local data was not backed by live OSV, unless the
        operator opted out with ``--allow-stale-db`` / ``AGENT_BOM_ALLOW_STALE_DB``.
        """
        return self.outdated and not self.complete and not vuln_freshness.allow_stale_db()

    def stale_message(self) -> str:
        return f"{self.reason} {_OPT_OUT_HINT}"


def _snapshot(offline: bool) -> VulnDataFreshness | None:
    try:
        return vuln_freshness.compute_freshness(offline=offline)
    except Exception as exc:  # noqa: BLE001 — a failed probe must fail closed, not crash the lookup
        _logger.warning("Vuln-data freshness probe failed; treating local data as outdated: %s", type(exc).__name__)
        return None


def _untrusted(snapshot: VulnDataFreshness | None) -> bool:
    return snapshot is None or local_db_outdated(snapshot)


def local_db_untrusted(*, offline: bool = False) -> bool:
    """True when local advisories must not stand alone (outdated, or freshness unknown)."""
    return _untrusted(_snapshot(offline))


def _condition(snapshot: VulnDataFreshness | None) -> str:
    if snapshot is None:
        return "The age of local vulnerability data could not be determined"
    text = f"Local vulnerability data is {local_data_age_text(snapshot)}"
    return f"{text}, and {snapshot.integrity_issue}" if snapshot.integrity_issue else text


def local_hits_line(count: int, *, offline: bool, prefer_local_db: bool, demo: bool) -> str:
    """Console line for advisories matched locally; never a check mark on outdated data."""
    noun = "vulnerability found" if count == 1 else "vulnerabilities found"
    mode_note = " (offline mode)" if offline else " (local advisory cache)" if prefer_local_db else ""
    if demo:
        return f"  [green]✓[/green] Demo advisory DB: {count} {noun}{mode_note}"
    snapshot = _snapshot(offline)
    if _untrusted(snapshot):
        label = "freshness unknown" if snapshot is None else local_data_age_text(snapshot)
        return f"  [yellow]⚠[/yellow] Local DB ({label}): {count} {noun}{mode_note}"
    return f"  [green]✓[/green] Local DB: {count} {noun}{mode_note}"


def _lookup_gap(coverage_warnings: list[dict[str, Any]], *, offline: bool) -> bool:
    """Mirror the ``check`` fail-closed gates: each gap kind only counts in its own mode."""
    kinds = {warning.get("kind") for warning in coverage_warnings}
    if "package_version_gap" in kinds:
        return True
    return "offline_ecosystem_gap" in kinds if offline else "remote_lookup_gap" in kinds


def _osv_answered() -> bool:
    """Whether live OSV (or its response cache) actually answered during this scan."""
    performance = peek_scan_performance()
    return bool(performance.get("osv_batches_answered") or performance.get("osv_cache_hits"))


def check_data_evidence(*, offline: bool, coverage_warnings: list[dict[str, Any]]) -> CheckDataEvidence:
    """Classify a finished package lookup as complete or possibly incomplete.

    Untrusted local data (outdated, newer schema, unreadable or unknown
    freshness) is complete only when the scanner could also consult live OSV
    for the package; offline runs and failed remote lookups leave the answer
    resting on that data, which is reported, never hidden.
    """
    offline = offline or offline_env()
    snapshot = _snapshot(offline)
    untrusted = _untrusted(snapshot)
    condition = _condition(snapshot)
    lookup_failed = any(warning.get("kind") == "remote_lookup_error" for warning in coverage_warnings)
    if untrusted and offline:
        status, reason = "incomplete", f"{condition} and OSV was not consulted (offline); results may be incomplete."
    elif untrusted and lookup_failed:
        status, reason = "incomplete", f"{condition} and the live OSV lookup failed; results may be incomplete."
    elif untrusted and not _osv_answered():
        status, reason = "incomplete", f"{condition} and live OSV did not answer for this package; results may be incomplete."
    elif _lookup_gap(coverage_warnings, offline=offline):
        status, reason = "incomplete", "Advisory lookup coverage was incomplete; results may be incomplete."
    elif untrusted:
        status, reason = "complete", f"{condition}; live OSV answered for this package and was merged in."
    else:
        status, reason = "complete", ""
    if untrusted:
        hint = _UPDATE_HINT if snapshot is not None and not snapshot.integrity_issue else _INTEGRITY_HINT
        reason = f"{reason} {hint}"
    freshness = snapshot.to_dict() if snapshot is not None else None
    return CheckDataEvidence(freshness=freshness, status=status, reason=reason, outdated=untrusted)


def record_untrusted_local_data(*, offline: bool, demo: bool) -> None:
    """Record a coverage gap when a scan rested on untrusted local data without live OSV.

    ``scan``, the API and MCP fold coverage warnings into an incomplete
    ``scan_run`` outcome, so this is what makes them fail closed. The
    ``--allow-stale-db`` / ``AGENT_BOM_ALLOW_STALE_DB`` opt-out suppresses it.
    """
    if demo or vuln_freshness.allow_stale_db():
        return
    offline = offline or offline_env()
    snapshot = _snapshot(offline)
    if not _untrusted(snapshot) or (not offline and _osv_answered()):
        return
    consulted = "OSV was not consulted (offline)" if offline else "live OSV did not answer"
    record_coverage_warning(
        {
            "kind": "stale_local_data",
            "release": "local-vuln-db:untrusted",
            "ecosystem": "vulnerability-data",
            "detail": f"{_condition(snapshot)} and {consulted}; results may be incomplete. {_OPT_OUT_HINT}",
        }
    )
