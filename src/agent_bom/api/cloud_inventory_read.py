"""Read-only provider inventory response construction."""

from __future__ import annotations

from typing import Any

from agent_bom.api.cloud_response_helpers import _audit_metadata, _logger, _redact_summary
from agent_bom.core.settings import env_raw

_INVENTORY_PROVIDERS = ("aws", "azure", "gcp", "snowflake")


def _snowflake_inventory() -> tuple[dict[str, Any], dict[str, Any]]:
    """Project Snowflake estate discovery into the canonical inventory summary.

    Snowflake discovery returns a list of AI resources (Cortex agents / search
    services, native MCP servers, notebooks, Streamlit apps, Snowpark package
    environments) rather than the infra buckets/instances/roles/users the other
    providers enumerate. To keep one consistent schema across providers, the
    discovered resources are projected onto the identical summary fields the
    aws/azure/gcp path emits (``_summarize_inventory_payload``): their count is
    surfaced as ``resource_count`` while the infra ``node_summary`` keys stay
    zero (Snowflake exposes none of those node types) and ``identity_count`` is
    zero (IAM/role enumeration is a separate governance discovery, not part of
    the inventory sweep).

    Graceful degradation mirrors the CIS branch: a disabled inventory gate, an
    absent ``snowflake-connector-python``, or missing account credentials yields
    a clear non-``ok`` status with zero resources — never a raise, never a 500.

    Returns ``(summary, raw_payload)`` where ``raw_payload`` carries the
    ``discovery_envelope`` the shared ``_audit_metadata`` roll-up consumes.
    """
    from agent_bom.cloud import CloudDiscoveryError, snowflake

    node_summary = {"buckets": 0, "instances": 0, "security_groups": 0, "roles": 0, "users": 0}

    def _summary(status: str, account: str | None, resource_count: int, warning_count: int) -> dict[str, Any]:
        return {
            "provider": "snowflake",
            "status": status,
            "account": account,
            "region": "",
            "resource_count": resource_count,
            "identity_count": 0,
            "node_summary": dict(node_summary),
            "warnings": (
                [f"{warning_count} provider discovery warning(s) — run via CLI/MCP or see server logs for detail."] if warning_count else []
            ),
        }

    if not snowflake.inventory_enabled():
        # Opt-in per provider; symmetric with the aws/azure/gcp disabled path.
        return _summary("disabled", None, 0, 0), {"status": "disabled", "discovery_envelope": None}

    try:
        agents, sf_warnings = snowflake.discover()
    except CloudDiscoveryError:
        # Connector absent — degrade to a clear "not configured" summary (HTTP
        # 200), never a 500. Log a canonical literal only (no user string / no
        # exception text) to avoid log injection + detail exposure.
        _logger.warning("Snowflake inventory unavailable for %s", "snowflake")
        return _summary("no_credentials", None, 0, 0), {"status": "no_credentials", "discovery_envelope": None}

    account = env_raw("SNOWFLAKE_ACCOUNT", "").strip() or None
    if agents:
        status = "partial" if sf_warnings else "ok"
    elif not account:
        status = "no_credentials"  # enabled but not configured (no account/creds)
    elif sf_warnings:
        status = "partial"  # configured, but discovery could not complete cleanly
    else:
        status = "ok"

    # Every agent carries the same run-level discovery envelope; surface the
    # first for the read-only audit roll-up (permissions_used / scope).
    envelope = None
    for agent in agents:
        candidate = getattr(agent, "discovery_envelope", None)
        if isinstance(candidate, dict):
            envelope = candidate
            break

    summary = _summary(status, account, len(agents), len(sf_warnings))
    raw_payload = {"status": status, "account_id": account, "discovery_envelope": envelope, "warnings": sf_warnings}
    return summary, raw_payload


def _build_inventory_payload(tenant_id: str, selected: list[str], scoped_region: str | None) -> dict[str, Any]:
    """Synchronous estate inventory body — runs off the event loop in a worker thread.

    Calls the same ``discover_inventory`` functions the CLI/MCP use and reduces
    each provider payload to the identical non-secret count shape. Kept as a
    module-level function (not a closure) so the offload seam is spy-able and the
    payload construction is unit-testable.
    """
    from agent_bom.cloud import aws_inventory, azure_inventory, gcp_inventory
    from agent_bom.cloud.inventory_summary import _summarize_inventory_payload, inventory_summary_status

    raw_payloads: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    if "aws" in selected:
        payload = aws_inventory.discover_inventory(region=scoped_region)
        raw_payloads.append(payload)
        summaries.append(_summarize_inventory_payload("aws", payload))
    if "azure" in selected:
        payload = azure_inventory.discover_inventory()
        raw_payloads.append(payload)
        summaries.append(_summarize_inventory_payload("azure", payload))
    if "gcp" in selected:
        payload = gcp_inventory.discover_inventory()
        raw_payloads.append(payload)
        summaries.append(_summarize_inventory_payload("gcp", payload))
    if "snowflake" in selected:
        # Snowflake discovery returns AI resources (Agents), not the infra
        # payload the other providers emit, so it is projected onto the same
        # canonical summary fields here rather than through
        # _summarize_inventory_payload. Graceful when the gate/creds are absent.
        sf_summary, sf_payload = _snowflake_inventory()
        raw_payloads.append(sf_payload)
        summaries.append(sf_summary)

    return {
        "schema_version": "cloud.inventory.summary.v1",
        "tenant_id": tenant_id,
        "status": inventory_summary_status(summaries),
        "total_resources": sum(s["resource_count"] for s in summaries),
        "total_identities": sum(s["identity_count"] for s in summaries),
        "providers": [_redact_summary(s) for s in summaries],
        "audit_metadata": _audit_metadata(raw_payloads),
        "note": (
            "Estate-wide inventory is opt-in per provider via AGENT_BOM_CLOUD_INVENTORY / "
            "AGENT_BOM_AZURE_INVENTORY / AGENT_BOM_GCP_INVENTORY / AGENT_BOM_SNOWFLAKE_INVENTORY. "
            "Reference-only counts; no resource secrets are returned. For Snowflake, resource_count "
            "reflects discovered AI resources (Cortex agents, MCP servers, notebooks); the infra "
            "node_summary keys stay zero."
        ),
    }
