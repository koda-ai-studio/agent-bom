"""Vuln-data freshness and completeness evidence for package lookups.

Local advisory hits are only a trustworthy standalone answer while the local
DB is fresh. The rule for "too old" is :func:`agent_bom.vuln_freshness.local_db_outdated`
(the same condition ``agent-bom db freshness`` warns on); this module turns it
into the console line the scanner prints and the structured evidence that
``check`` returns on every surface (CLI JSON, MCP, REST).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_bom import vuln_freshness
from agent_bom.domain.report_payloads import VulnerabilityFreshnessPayload
from agent_bom.vuln_freshness import local_data_age_text, local_db_outdated, offline_env

_UPDATE_HINT = "Run `agent-bom db update` to refresh it."


@dataclass(frozen=True)
class CheckDataEvidence:
    """What the vulnerability data behind one check was, and whether it was enough."""

    freshness: VulnerabilityFreshnessPayload
    status: str
    reason: str
    outdated: bool = False

    @property
    def complete(self) -> bool:
        return self.status == "complete"

    def completeness(self) -> dict[str, str]:
        return {"status": self.status, "reason": self.reason}


def local_hits_line(count: int, *, offline: bool, prefer_local_db: bool, demo: bool) -> str:
    """Console line for advisories matched locally; never a check mark on outdated data."""
    noun = "vulnerability found" if count == 1 else "vulnerabilities found"
    mode_note = " (offline mode)" if offline else " (local advisory cache)" if prefer_local_db else ""
    if demo:
        return f"  [green]✓[/green] Demo advisory DB: {count} {noun}{mode_note}"
    snapshot = vuln_freshness.compute_freshness(offline=offline)
    if local_db_outdated(snapshot):
        return f"  [yellow]⚠[/yellow] Local DB ({local_data_age_text(snapshot)}): {count} {noun}{mode_note}"
    return f"  [green]✓[/green] Local DB: {count} {noun}{mode_note}"


def _lookup_gap(coverage_warnings: list[dict[str, Any]], *, offline: bool) -> bool:
    """Mirror the ``check`` fail-closed gates: each gap kind only counts in its own mode."""
    kinds = {warning.get("kind") for warning in coverage_warnings}
    if "package_version_gap" in kinds:
        return True
    return "offline_ecosystem_gap" in kinds if offline else "remote_lookup_gap" in kinds


def check_data_evidence(*, offline: bool, coverage_warnings: list[dict[str, Any]]) -> CheckDataEvidence:
    """Classify a finished package lookup as complete or possibly incomplete.

    An outdated local DB is complete only when the scanner could also consult
    live OSV for the package; offline runs and failed remote lookups leave the
    answer resting on old local data, which is reported, never hidden.
    """
    offline = offline or offline_env()
    snapshot = vuln_freshness.compute_freshness(offline=offline)
    outdated = local_db_outdated(snapshot)
    age = local_data_age_text(snapshot)
    lookup_failed = any(warning.get("kind") == "remote_lookup_error" for warning in coverage_warnings)
    if outdated and offline:
        status, reason = "incomplete", f"Local vulnerability data is {age} and OSV was not consulted (offline); results may be incomplete."
    elif outdated and lookup_failed:
        status, reason = "incomplete", f"Local vulnerability data is {age} and the live OSV lookup failed; results may be incomplete."
    elif _lookup_gap(coverage_warnings, offline=offline):
        status, reason = "incomplete", "Advisory lookup coverage was incomplete; results may be incomplete."
    elif outdated:
        status, reason = "complete", f"Local vulnerability data is {age}; live OSV was also queried for this package."
    else:
        status, reason = "complete", ""
    if outdated:
        reason = f"{reason} {_UPDATE_HINT}"
    return CheckDataEvidence(freshness=snapshot.to_dict(), status=status, reason=reason, outdated=outdated)
