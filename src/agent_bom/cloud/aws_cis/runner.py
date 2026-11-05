"""Region/coverage helpers shared by the CIS AWS single-region, enabled-region and org fan-out runners."""

from __future__ import annotations

from ._base import CheckStatus, CISBenchmarkReport, CISCheckResult

__all__ = ["_MAX_CIS_FANOUT_WORKERS", "_REGIONAL_CIS_CHECK_IDS"]

# Regional checks (EC2/RDS/KMS/logging/network) must run in every enabled region.
# Global IAM/S3/account checks run once on the home region only.
_REGIONAL_CIS_CHECK_IDS: frozenset[str] = frozenset(
    {
        "1.19",
        "1.20",
        "2.2.1",
        "2.3.1",
        "2.3.2",
        "2.4.1",
        "3.1",
        "3.2",
        "3.4",
        "3.5",
        "3.7",
        "3.9",
        "3.10",
        "3.11",
        "4.1",
        "4.2",
        "4.3",
        "4.4",
        "4.5",
        "4.6",
        "4.7",
        "4.8",
        "4.9",
        "4.10",
        "4.11",
        "4.12",
        "4.13",
        "4.14",
        "4.15",
        "4.16",
        "5.1",
        "5.2",
        "5.3",
        "5.4",
        "5.5",
    }
)

_STATUS_RANK = {
    CheckStatus.FAIL: 0,
    CheckStatus.ERROR: 1,
    CheckStatus.NO_DATA: 2,
    CheckStatus.PASS: 3,
    CheckStatus.NOT_APPLICABLE: 4,
}


def _mark_report_partial_for_evidence_gaps(report: CISBenchmarkReport) -> None:
    """Keep check-level read gaps from being summarized as complete coverage."""
    error_count = report.errored
    if not error_count:
        return
    report.completeness = "partial" if report.account_id else "unavailable"
    warning = f"CIS evidence coverage is incomplete: {error_count} check(s) could not be evaluated."
    if warning not in report.warnings:
        report.warnings.append(warning)


def _withhold_unverified_identity(report: CISBenchmarkReport) -> None:
    """Without a verified account boundary, no affirmative result can stand."""
    report.warnings.append("AWS account identity could not be verified; affirmative CIS results were withheld.")
    for check in report.checks:
        if check.status in {CheckStatus.PASS, CheckStatus.NO_DATA} or (check.status is CheckStatus.NOT_APPLICABLE and check.vacuous):
            check.status = CheckStatus.ERROR
            check.evidence = (
                "AWS account identity could not be verified with STS GetCallerIdentity; "
                "PASS withheld because the evaluated account boundary is unknown."
            )


def _demote_passes_to_unknown(
    report: CISBenchmarkReport,
    *,
    check_ids: frozenset[str] | None,
    reason: str,
) -> None:
    """Replace only optimistic PASS states when the evidence boundary is incomplete."""
    for check in report.checks:
        if check.status is not CheckStatus.PASS and not (check.status is CheckStatus.NOT_APPLICABLE and check.vacuous):
            continue
        if check_ids is not None and check.check_id not in check_ids:
            continue
        check.status = CheckStatus.ERROR
        check.evidence = reason


def _merge_regional_cis_check(existing: CISCheckResult, incoming: CISCheckResult, region: str) -> CISCheckResult:
    """Merge two results for the same check_id across regions (worst status wins)."""
    if _STATUS_RANK[incoming.status] < _STATUS_RANK[existing.status]:
        winner = incoming
        other = existing
    else:
        winner = existing
        other = incoming
    suffix = f"[{region}] {other.evidence}" if other.evidence else f"[{region}]"
    evidence = winner.evidence
    if suffix not in evidence:
        evidence = f"{evidence}; {suffix}" if evidence else suffix
    return CISCheckResult(
        check_id=winner.check_id,
        title=winner.title,
        status=winner.status,
        severity=winner.severity,
        evidence=evidence,
        resource_ids=list(dict.fromkeys([*winner.resource_ids, *other.resource_ids]))[:20],
        account_id=winner.account_id or other.account_id,
        network_exposure=winner.network_exposure or other.network_exposure,
        remediation=winner.remediation or other.remediation,
        vacuous=winner.vacuous,
    )


# Bounded concurrency for the multi-account fan-out — mirrors the AWS inventory
# fan-out's thread pool so an org-wide CIS run collapses the per-account
# latencies instead of summing them.
_MAX_CIS_FANOUT_WORKERS = 8
