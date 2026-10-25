"""Databricks token checks using workspace policy and owner-scoped PAT metadata."""

from __future__ import annotations

from typing import Any

from agent_bom.security import sanitize_error

from .aws_cis_benchmark import CheckStatus, CISCheckResult

_IAM_SECTION = "1 - Identity and Access Management"


def _check_1_3(ws: Any) -> CISCheckResult:
    """1.3 — Ensure Personal Access Token expiry policy is enforced."""
    result = CISCheckResult(
        check_id="1.3",
        title="Enforce Personal Access Token expiry policy",
        status=CheckStatus.ERROR,
        severity="medium",
        cis_section=_IAM_SECTION,
        recommendation="Set a PAT expiry policy: Workspace Settings > Advanced > "
        "Access tokens > Token lifetime (maximum 90 days recommended).",
    )
    try:
        settings = ws.workspace_conf.get_status(keys="maxTokenLifetimeDays")
        raw_days = settings.get("maxTokenLifetimeDays") if isinstance(settings, dict) else None
        if not isinstance(raw_days, (str, int)) or isinstance(raw_days, bool):
            result.evidence = "Workspace configuration did not expose a token lifetime policy."
            return result
        days = int(raw_days)
        if days < 0:
            result.evidence = "Workspace configuration returned an invalid token lifetime policy."
        elif 0 < days <= 90:
            result.status = CheckStatus.PASS
            result.evidence = f"Maximum lifetime for new PATs is {days} days; existing tokens are not covered by this policy check."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = (
                "No custom PAT lifetime limit is set; the workspace default does not demonstrate a maximum of 90 days."
                if days == 0
                else f"Maximum lifetime for new PATs is {days} days, exceeding the recommended 90 days."
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PAT policy: {sanitize_error(exc, generic=True)}"
    return result


def _check_1_4(ws: Any) -> CISCheckResult:
    """1.4 — Ensure service principals use short-lived tokens."""
    result = CISCheckResult(
        check_id="1.4",
        title="Ensure service principals use short-lived or federated tokens",
        status=CheckStatus.ERROR,
        severity="medium",
        cis_section=_IAM_SECTION,
        recommendation="Replace long-lived service principal PATs with OAuth M2M tokens or workload identity federation where possible.",
    )
    try:
        sps = list(ws.service_principals.list() or [])
        if not sps:
            result.status = CheckStatus.PASS
            result.evidence = "No service principals found."
            return result
        import time

        owners = {str(sp.id) for sp in sps if getattr(sp, "id", None) is not None}
        if len(owners) != len(sps):
            result.evidence = "Service principal identities are incomplete; token ownership cannot be established."
            return result
        tokens = list(ws.token_management.list() or [])
        deadline = int(time.time() * 1000) + 90 * 24 * 60 * 60 * 1000
        long_lived, unknown, matched = 0, 0, 0
        for token in tokens:
            owner = getattr(token, "owner_id", None)
            if owner is None:
                unknown += 1
            elif str(owner) in owners:
                matched += 1
                expiry = getattr(token, "expiry_time", None)
                if not isinstance(expiry, int) or isinstance(expiry, bool):
                    unknown += 1
                elif expiry <= 0 or expiry > deadline:
                    long_lived += 1
        if long_lived:
            result.status = CheckStatus.FAIL
            result.evidence = f"{long_lived} service principal PAT(s) have no expiry or expire more than 90 days from this scan."
            if unknown:
                result.evidence += f" {unknown} token(s) also have incomplete ownership or expiry evidence."
        elif unknown:
            result.evidence = (
                f"{unknown} token(s) have incomplete ownership or expiry evidence; service principal token posture is unknown."
            )
        else:
            result.status = CheckStatus.PASS
            result.evidence = (
                f"{matched} enumerated service principal PAT(s): none expire more than 90 days from this scan. "
                "This does not establish OAuth use or the original token lifetime."
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check service principal tokens: {sanitize_error(exc, generic=True)}"
    return result
