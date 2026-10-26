"""Console rendering of kernel-header CVE groups (see :mod:`agent_bom.output.kernel_headers`)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.markup import escape
from rich.rule import Rule

from agent_bom.output.brand_tokens import lane_title
from agent_bom.output.finding_views import package_name, package_version, sanitize_output_text
from agent_bom.output.kernel_headers import KernelHeaderGroup, kernel_header_groups

if TYPE_CHECKING:
    from agent_bom.finding import Finding
    from agent_bom.models import AIBOMReport

_MAX_LISTED_IDS = 5


def collapse_kernel_header_findings(report: AIBOMReport, findings: list[Finding]) -> tuple[list[Finding], list[KernelHeaderGroup]]:
    """Drop collapsible kernel-header CVEs from ``findings`` and return their groups.

    KEV and critical kernel-header CVEs are never collapsed.
    """
    from agent_bom.vex import active_blast_radii

    if not report.blast_radii:
        return findings, []
    groups = kernel_header_groups(active_blast_radii(report.blast_radii))
    if not groups:
        return findings, []
    collapsed = {(str(br.vulnerability.id), br.package.name, br.package.version) for group in groups for br in group.collapsed}
    kept = [f for f in findings if (str(f.cve_id or f.id), package_name(f), package_version(f)) not in collapsed]
    return kept, groups


def _listed(ids: list[str]) -> str:
    shown = ", ".join(escape(sanitize_output_text(value)) for value in ids[:_MAX_LISTED_IDS])
    more = f" +{len(ids) - _MAX_LISTED_IDS}" if len(ids) > _MAX_LISTED_IDS else ""
    return f"{shown}{more}"


def kernel_header_group_line(group: KernelHeaderGroup) -> str:
    """Two bounded lines: packages, distro and totals, then every KEV/critical called out."""
    packages = ", ".join(escape(sanitize_output_text(pkg)) for pkg in group.packages[:3])
    if len(group.packages) > 3:
        packages += f" +{len(group.packages) - 3}"
    severities = " · ".join(f"{count} {name}" for name, count in group.severity_counts.items())
    headline = f"  [bold]Kernel-header group[/bold] {packages} ({escape(group.distro_label)}) · {group.total} CVEs: {severities}"
    details: list[str] = []
    if group.kev_ids:
        details.append(f"[red bold]{len(group.kev_ids)} KEV ({_listed(group.kev_ids)})[/red bold]")
    if group.critical_ids:
        details.append(f"[red]{len(group.critical_ids)} critical ({_listed(group.critical_ids)})[/red]")
    if details:
        details[-1] += " shown as rows"
    details.append(f"{group.collapsed_count} collapsed — -f json, sarif or cyclonedx lists every CVE")
    return headline + "\n    " + " · ".join(details)


def kernel_header_summary_lines(blast_radii: list) -> list[str]:
    """Scan-verdict sub-lines saying how much of the CVE total is kernel-header CVEs."""
    from agent_bom.vex import active_blast_radii

    lines = []
    for group in kernel_header_groups(active_blast_radii(blast_radii)):
        packages = ", ".join(escape(sanitize_output_text(pkg)) for pkg in group.packages[:3])
        lines.append(
            f"    [dim]↳ {group.total} of these are kernel-header CVEs ({packages}, {escape(group.distro_label)}); "
            "the findings table groups them into one row[/dim]"
        )
    return lines


def print_findings_heading(title: str, groups: list[KernelHeaderGroup]) -> None:
    """The findings-table rule, followed by one block per kernel-header group."""
    from agent_bom.output import console

    console.print(Rule(lane_title("analyze", title), style="dim"))
    for group in groups:
        console.print(kernel_header_group_line(group))


def print_kernel_groups_only(groups: list[KernelHeaderGroup]) -> None:
    """Every active CVE was a collapsible kernel-header CVE: still show the groups."""
    if groups:
        from agent_bom.output import console

        console.print()
        print_findings_heading("Findings (kernel-header CVEs only)", groups)
