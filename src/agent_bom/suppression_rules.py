"""Tenant-scoped finding suppression rules.

Suppression is modeled as an evidence overlay, not deletion. A matching rule
sets the blast-radius item to non-actionable and preserves the original risk
score for audit/export consumers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.api.exception_store import ExceptionStore, VulnException
from agent_bom.core.iac_exceptions import IaCException, parse_resource_selector
from agent_bom.core.suppression_score import clear_blast_radius_suppression, mark_blast_radius_suppressed
from agent_bom.core.timestamps import parse_identity_timestamp

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius

_SUPPRESSING_FEEDBACK_STATES = {
    "false_positive",
    "accepted_risk",
    "not_affected",
    "not_applicable",
    "fixed_verified",
}


def feedback_state_from_reason(reason: str) -> tuple[str | None, str]:
    """Parse ``[finding_feedback:state] reason`` values from the exception store."""
    marker = "[finding_feedback:"
    if not reason.startswith(marker):
        return None, reason
    closing = reason.find("]")
    if closing <= len(marker):
        return None, reason
    state = reason[len(marker) : closing].strip()
    if state == "not_applicable":
        state = "not_affected"
    clean_reason = reason[closing + 1 :].strip()
    return state or None, clean_reason


def is_suppressing_exception(exc: VulnException) -> bool:
    """Return whether an exception/feedback row suppresses scanner actionability."""
    state, _reason = feedback_state_from_reason(exc.reason)
    return state in _SUPPRESSING_FEEDBACK_STATES or state is None


def apply_tenant_suppression_rules(
    blast_radii: list["BlastRadius"],
    store: ExceptionStore,
    *,
    tenant_id: str = "default",
) -> dict[str, int]:
    """Apply tenant-scoped exception/feedback rules to blast-radius findings.

    Findings remain in the list with suppression metadata. This preserves
    original evidence while preventing suppressed findings from counting as
    actionable in downstream output.
    """
    summary = {"evaluated": len(blast_radii), "suppressed": 0}
    for br in blast_radii:
        # Re-evaluate persisted overlays against current approval and expiry.
        if br.suppressed and br.suppression_state != "vex":
            clear_blast_radius_suppression(br)
        server_names = [server.name for server in br.affected_servers] or [""]
        match = next(
            (
                entry
                for identity in (br.package.purl, f"{br.package.name}@{br.package.version}", br.package.name)
                if identity and (entry := _find_matching_exception(store, br.vulnerability.id, identity, server_names, tenant_id))
            ),
            None,
        )
        if match is None or not is_suppressing_exception(match):
            continue
        state, reason = feedback_state_from_reason(match.reason)
        mark_blast_radius_suppressed(br, suppression_id=match.exception_id, state=state or "exception", reason=reason or match.reason)
        summary["suppressed"] += 1
    return summary


def _find_matching_exception(
    store: ExceptionStore,
    vuln_id: str,
    package_name: str,
    server_names: list[str],
    tenant_id: str,
) -> VulnException | None:
    for server_name in server_names:
        match = store.find_matching(vuln_id, package_name, server_name=server_name, tenant_id=tenant_id)
        if match is not None:
            return match
    return None


def tenant_iac_exceptions(store: ExceptionStore, *, tenant_id: str) -> list[IaCException]:
    """The tenant's approved, unexpired IaC exceptions as the shared IaC exception model.

    Only records the approval contract activates (second approver, bounded
    expiry, exact rule, path/resource scope) are returned; a pending, revoked or
    expired record never suppresses anything. Every read is tenant-scoped.
    """
    exceptions: list[IaCException] = []
    for record in store.list_all(tenant_id=tenant_id):
        if record.tenant_id != tenant_id or not record.iac_suppression_active():
            continue
        try:
            selector = parse_resource_selector(record.iac_resource) if record.iac_resource else None
        except ValueError:
            continue
        expiry = parse_identity_timestamp(record.expires_at, require_timezone=True)
        exceptions.append(
            IaCException(
                rule=record.iac_rule_id.upper(),
                reason=record.reason,
                source="tenant",
                origin=f"tenant-exception/{record.exception_id}",
                path=record.iac_path or None,
                resource=selector,
                expires=expiry.date() if expiry else None,
                owner=record.requested_by or None,
                approved_by=record.approved_by or None,
                exception_id=record.exception_id,
            )
        )
    return exceptions
