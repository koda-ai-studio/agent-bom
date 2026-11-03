"""Console verdict and receipt for a scan whose correlated finding count is zero.

A zero can mean three different things: coverage gaps kept findings from being
confirmed, the default unfixed-OS-advisory policy removed every finding, or the
inventory is genuinely clean. Each gets its own line so a policy never reads as
a clean bill of health.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from agent_bom.coverage import record_scan_note
from agent_bom.evidence.scan_run import ScanOutcome, effective_scan_run
from agent_bom.scanners.state import peek_coverage_warnings, peek_scan_performance, peek_scan_warnings

UNFIXED_FLAG = "AGENT_BOM_INCLUDE_UNFIXED=1"


def suppressed_unfixed_os_findings() -> int:
    """Unfixed OS-package findings the default policy removed in this scan so far."""
    return int(peek_scan_performance().get("unfixed_os_findings_suppressed", 0))


def record_unfixed_suppression_receipt() -> None:
    """One scan note per scan, cumulative across scanner batches, naming the count and the flag."""
    count = suppressed_unfixed_os_findings()
    record_scan_note(
        ecosystem="os-packages",
        path="unfixed-advisories",
        reason="unfixed_os_suppressed",
        detail=f"{count} unfixed OS-package finding(s) (no-dsa/won't-fix) suppressed by default; set {UNFIXED_FLAG} to include them",
        replace=True,
    )


def no_fixable_vulnerabilities_line(suppressed: int) -> str:
    """Verdict for a scan whose only findings were policy-suppressed unfixed OS advisories."""
    return f"No fixable vulnerabilities found; {suppressed} unfixed OS-package finding(s) suppressed (set {UNFIXED_FLAG} to include)"


def zero_findings_verdict(agents: list[Any]) -> str:
    """Rich-markup console line for a scan that confirmed no vulnerabilities."""
    run = effective_scan_run(SimpleNamespace(agents=agents, coverage_warnings=peek_coverage_warnings()))
    if run.outcome is not ScanOutcome.COMPLETE or peek_scan_warnings():
        return "  [yellow]No vulnerabilities confirmed; coverage gaps limit this assessment[/yellow]"
    if suppressed := suppressed_unfixed_os_findings():
        return f"  [yellow]{no_fixable_vulnerabilities_line(suppressed)}[/yellow]"
    return "  [green]✓ No known vulnerabilities found[/green]"


def vulnerability_summary_line(total_vulns: int, findings_count: int, *, agents: list[Any], blast_radii: list[Any] | None) -> str:
    """Count findings (one advisory affecting one package), never raw advisory matches.

    Raw matches double-count rows merged from several advisory sources, so a
    bare match total next to a smaller finding count reads as a contradiction.
    """
    if blast_radii:
        count = len(blast_radii)
        packages = len({(br.package.ecosystem, br.package.name, br.package.version) for br in blast_radii})
        advisories = len({br.vulnerability.id for br in blast_radii})
        noun = "vulnerability" if count == 1 else "vulnerabilities"
        distinct = f" ({advisories} distinct advisor{'y' if advisories == 1 else 'ies'})" if advisories != count else ""
        return f"  [red]⚠ Found {count} known {noun} in {packages} package{'s' if packages != 1 else ''}{distinct}[/red]"
    if total_vulns or findings_count:
        found = findings_count or total_vulns
        return f"  [red]⚠ Found {found} known vulnerabilit{'y' if found == 1 else 'ies'}[/red]"
    return zero_findings_verdict(agents)


def unconfirmed_matches_line(count: int) -> str | None:
    """Explain local matches demoted to possibly affected, so a match count never silently vanishes."""
    if not count:
        return None
    noun = "match" if count == 1 else "matches"
    return (
        f"  [yellow]⚠[/yellow] {count} local advisory {noun} could not be confirmed against a version range; "
        "reported as possibly affected, not as findings. Refresh with `agent-bom db update` or scan online."
    )
