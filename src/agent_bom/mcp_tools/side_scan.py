"""MCP side-scan execution tool — trigger a cross-cloud agentless disk side-scan.

Exposes the same shipped ``run_provider_side_scan`` executor the CLI
(``agent-bom cloud side-scan``) and the REST ``POST /v1/cloud/side-scan``
endpoint drive. No new business logic lives here — this is the headless MCP
surface over the existing executor + durable lifecycle store.

Security posture (non-negotiable):
- Opt-in mutation family, never touching the scanned disk or image: agent-bom
  creates a temp snapshot/disk, mounts it on an in-account collector read-only,
  records SBOM + CVE (per owning VM) + secret metadata only, and tears every
  owned temporary resource down. The graph snapshot is persisted by the REST
  route; this tool returns the same bounded package/CVE record.
- Credentials are never accepted here; the executor resolves separately scoped
  lifecycle credentials from the provider's default chain
  (``credentialed_smoke=False``).
- Admin-gated destructive write at the dispatch layer (``cloud:write`` scope).
- Fail-closed and honest: side-scan OFF → ``disabled``; missing provider extra /
  credentials → ``unavailable``; never a false clean-workload assertion.

AWS EBS keeps its own CLI entrypoint (its results are not persisted to the shared
lifecycle store), so this tool handles only ``azure`` | ``gcp``.
"""

from __future__ import annotations

import asyncio
import json
import logging

from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)

_SUPPORTED = {"azure", "gcp"}


async def cloud_side_scan_impl(
    *,
    provider: str = "",
    target_id: str = "",
    target_type: str = "disk",
    account_id: str = "",
    location: str = "",
    collector_id: str = "",
    collector_resource_group: str = "",
    region: str = "",
    idempotency_key: str = "",
    scan_secrets_enabled: bool = True,
    tenant_id: str = "default",
    operator_role: str = "viewer",
    operator_scopes: str = "",
    reason: str = "",
    _truncate_response,
    _authenticated_actor: str = "",
) -> str:
    """Run one Azure/GCP agentless disk side-scan through the shared executor."""
    from agent_bom.cloud.side_scan import SideScanConfigError, SideScanDisabledError
    from agent_bom.cloud.side_scan_lifecycle import get_side_scan_state_store, new_side_scan_execution
    from agent_bom.cloud.side_scan_targets import AZURE_IMAGE_UNSUPPORTED, run_provider_side_scan

    resolved_tenant = resolve_mcp_tool_tenant_id(tenant_id)
    prov = provider.strip().lower()
    if prov not in _SUPPORTED:
        return json.dumps(
            {
                "status": "rejected",
                "error": "provider must be 'azure' or 'gcp' (AWS EBS uses the CLI side-scan entrypoint).",
            }
        )
    missing = [
        label
        for label, value in (
            ("target_id", target_id),
            ("account_id", account_id),
            ("location", location),
            ("collector_id", collector_id),
        )
        if not str(value).strip()
    ]
    if target_type not in {"disk", "image"}:
        return json.dumps({"status": "rejected", "error": "target_type must be 'disk' or 'image'"})
    if prov == "azure" and target_type == "image":
        return json.dumps({"status": "rejected", "error": AZURE_IMAGE_UNSUPPORTED})
    if prov == "azure" and not collector_resource_group.strip():
        missing.append("collector_resource_group")
    if missing:
        return json.dumps({"status": "rejected", "error": f"missing required argument(s): {', '.join(missing)}"})

    import uuid as _uuid

    idem = idempotency_key.strip() or _uuid.uuid4().hex
    execution_id = new_side_scan_execution(
        tenant_id=resolved_tenant,
        provider=prov,  # type: ignore[arg-type]
        account_id=account_id.strip(),
        target_id=target_id.strip(),
        collector_id=collector_id.strip(),
        idempotency_key=idem,
    ).execution_id

    try:
        results = await run_provider_side_scan(
            provider=prov,  # type: ignore[arg-type]
            target_id=target_id.strip(),
            target_type=target_type,
            account_id=account_id.strip(),
            location=location.strip(),
            collector_id=collector_id.strip(),
            tenant_id=resolved_tenant,
            idempotency_key=idem,
            collector_resource_group=collector_resource_group.strip() or None,
            region=region.strip() or None,
            scan_secrets_enabled=scan_secrets_enabled,
        )
    except SideScanDisabledError as exc:
        return _truncate_response(
            json.dumps(
                {
                    "status": "disabled",
                    "execution_id": execution_id,
                    "provider": prov,
                    "message": str(exc),
                    "enable": "Set AGENT_BOM_SIDESCAN=1 and provide a scoped snapshot role plus an in-account collector.",
                }
            )
        )
    except SideScanConfigError as exc:
        return _truncate_response(
            json.dumps(
                {
                    "status": "unavailable",
                    "execution_id": execution_id,
                    "provider": prov,
                    "reason": sanitize_error(exc),
                }
            )
        )
    except asyncio.CancelledError:  # pragma: no cover - cooperative cancellation
        raise
    except Exception as exc:  # noqa: BLE001 - never leak a raw traceback for a provider fault
        logger.warning("MCP cloud_side_scan failed")
        return _truncate_response(json.dumps({"status": "error", "execution_id": execution_id, "error": sanitize_error(exc)}))

    store = get_side_scan_state_store()
    record = store.get(tenant_id=resolved_tenant, execution_id=execution_id)
    payload = {
        "status": record.status.value if record is not None else "unknown",
        "execution_id": execution_id,
        "provider": prov,
        "tenant_id": resolved_tenant,
        "result": _result_summary(results),
    }
    if record is not None:
        payload["execution"] = record.to_dict()
        payload["evidence"] = record.to_evidence_dict()
    return _truncate_response(json.dumps(payload, indent=2, default=str))


def _result_summary(results: list) -> dict:
    """Metadata-only run summary plus the bounded package/CVE record — the API's exact shape."""
    from agent_bom.cloud.side_scan_inventory import side_scan_response

    return side_scan_response(results)
