"""Non-secret inventory counts shared by provider connection and MCP reads."""

from __future__ import annotations

from typing import Any

_INVENTORY_RESOURCE_KEYS = ("buckets", "instances", "security_groups", "dspm_databases")
_INVENTORY_IDENTITY_KEYS = ("roles", "users")
_PUBLIC_INVENTORY_STATUSES = {
    "ok",
    "unknown",
    "disabled",
    "boto3_missing",
    "no_credentials",
    "partial",
}


def _summarize_inventory_payload(provider: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Reduce a per-provider inventory payload to non-secret counts.

    Reuses the builder's canonical-shape normalizer so Azure/GCP provider-native
    keys map to the same resource/identity lists the graph counts.
    """
    from agent_bom.graph.builder import _normalize_cloud_inventory

    normalized = _normalize_cloud_inventory(payload)
    resource_count = sum(len(normalized.get(key) or []) for key in _INVENTORY_RESOURCE_KEYS)
    identity_count = sum(len(normalized.get(key) or []) for key in _INVENTORY_IDENTITY_KEYS)
    # Provider discovery warnings are built from caught exceptions
    # (``sanitize_discovery_warning(exc)``), so they must not be surfaced verbatim
    # in a summary that flows to REST/MCP responses. Emit a count-derived,
    # exception-free notice instead; full warnings stay in the server log.
    warning_count = len(payload.get("warnings") or [])
    public_warnings = [f"{warning_count} provider discovery warning(s) — see server logs for detail."] if warning_count else []
    raw_status = str(payload.get("status", "unknown") or "unknown").strip().lower()
    public_status = raw_status if raw_status in _PUBLIC_INVENTORY_STATUSES else "unknown"
    if public_status == "ok" and (warning_count or payload.get("missing_permissions")):
        public_status = "partial"
    summary = {
        "provider": provider,
        "status": public_status,
        "account": payload.get("account_id") or payload.get("subscription_id") or payload.get("project_id") or None,
        "region": payload.get("region") or "",
        "resource_count": resource_count,
        "identity_count": identity_count,
        "node_summary": {
            "buckets": len(normalized.get("buckets") or []),
            "instances": len(normalized.get("instances") or []),
            "security_groups": len(normalized.get("security_groups") or []),
            "roles": len(normalized.get("roles") or []),
            "users": len(normalized.get("users") or []),
        },
        "warnings": public_warnings,
    }
    authorization_evidence = payload.get("authorization_evidence")
    if isinstance(authorization_evidence, dict):
        from agent_bom.api.metrics import record_authorization_evidence
        from agent_bom.cloud.authorization_evidence import (
            authorization_evidence_gap_reason_codes,
            summarize_authorization_evidence,
        )

        evidence_summary = summarize_authorization_evidence(authorization_evidence)
        summary["authorization_evidence"] = evidence_summary.to_dict()
        record_authorization_evidence(
            provider=str(provider).strip().lower(),
            status=evidence_summary.status.value,
            reason_codes=authorization_evidence_gap_reason_codes(authorization_evidence),
        )
    return summary
