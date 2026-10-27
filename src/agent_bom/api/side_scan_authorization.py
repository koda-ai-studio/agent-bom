"""Bind server-side snapshot mutations to tenant connections and operator grants."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from agent_bom.api.connection_store import get_connection_store
from agent_bom.cloud.connection_workload import broker_side_scan_binding, resolve_binding
from agent_bom.cloud.side_scan import SideScanConfigError
from agent_bom.cloud.side_scan_lifecycle import new_side_scan_execution
from agent_bom.cloud.side_scan_targets import _default_provider_clients


def _resolve(tenant_id: str, connection_id: str, scope: dict[str, Any]):
    record = get_connection_store().get(tenant_id, connection_id) if connection_id else None
    if record is None or record.id != connection_id or record.tenant_id != tenant_id or record.auth_params.get("demo") is True:
        raise SideScanConfigError("A tenant-owned, non-synthetic connection is required for side-scan.")
    binding = resolve_binding(record)
    grant = binding.side_scan
    if (
        grant is None
        or binding.provider != scope["provider"]
        or binding.scope_id != scope["account_id"]
        or binding.inventory_scope != "account"
        or scope["target_id"] not in grant.targets
        or scope["collector_id"] not in grant.collectors
        or scope["location"] not in grant.locations
        or (binding.provider == "azure" and scope["collector_resource_group"] not in grant.collector_resource_groups)
    ):
        raise SideScanConfigError("Side-scan scope is not authorized by the connection lifecycle grant.")
    target, account = scope["target_id"], scope["account_id"]
    if binding.provider == "azure":
        valid_target = target.lower().startswith(f"/subscriptions/{account}/resourcegroups/".lower())
    else:
        target = target.removeprefix("https://www.googleapis.com/compute/v1/").removeprefix("https://compute.googleapis.com/compute/v1/")
        valid_target = target.startswith(f"projects/{account}/")
    if not valid_target or any(part in {".", ".."} for part in target.split("/")):
        raise SideScanConfigError("Side-scan target is outside the bound provider account.")
    fingerprint = hashlib.sha256(
        json.dumps({"connection_id": record.id, "binding": binding.model_dump()}, sort_keys=True).encode()
    ).hexdigest()
    return binding, fingerprint


def authorize_side_scan(
    *,
    tenant_id: str,
    connection_id: str,
    provider: str,
    account_id: str,
    target_id: str,
    collector_id: str,
    location: str,
    collector_resource_group: str | None = None,
) -> dict[str, Any]:
    """Authorize before ledger writes; recheck the same grant before creating clients."""
    scope = dict(
        provider=provider,
        account_id=account_id.strip(),
        target_id=target_id.strip(),
        collector_id=collector_id.strip(),
        location=location.strip(),
        collector_resource_group=(collector_resource_group or "").strip(),
    )
    try:
        _, fingerprint = _resolve(tenant_id, connection_id, scope)
    except Exception as exc:
        raise SideScanConfigError("Side-scan connection authorization is unavailable or denied.") from exc

    def client_factory(provider: str, *, account_id: str, region: str | None) -> dict[str, Any]:
        try:
            binding, current = _resolve(tenant_id, connection_id, scope)
            if current != fingerprint or provider != scope["provider"] or account_id != scope["account_id"]:
                raise SideScanConfigError("Side-scan authorization changed before execution.")
            credential = broker_side_scan_binding(binding)
            if credential is None:
                raise SideScanConfigError("Side-scan credential is unavailable.")
            return _default_provider_clients(provider, account_id=account_id, region=region, credential=credential)
        except Exception as exc:
            raise SideScanConfigError("Side-scan bound credentials are unavailable or denied.") from exc

    return {"client_factory": client_factory, "authorization_ref": f"{connection_id}:{fingerprint}"}


def prepare_side_scan_request(tenant_id: str, body: Any) -> tuple[str, dict[str, Any]]:
    """Bind one REST request and derive its deterministic execution identity."""
    authorization = authorize_side_scan(
        tenant_id=tenant_id,
        connection_id=body.connection_id,
        provider=body.provider,
        account_id=body.account_id,
        target_id=body.target_id,
        collector_id=body.collector_id,
        location=body.location,
        collector_resource_group=body.collector_resource_group,
    )
    identity = dict(
        tenant_id=tenant_id,
        provider=body.provider,
        account_id=body.account_id.strip(),
        target_id=body.target_id.strip(),
        collector_id=body.collector_id.strip(),
        idempotency_key=(body.idempotency_key or uuid.uuid4().hex).strip(),
    )
    execution_id = new_side_scan_execution(**identity).execution_id
    return execution_id, dict(
        **authorization,
        **identity,
        location=body.location.strip(),
        collector_resource_group=body.collector_resource_group,
        region=body.region,
        scan_secrets_enabled=body.scan_secrets_enabled,
        target_type=body.target_type,
    )
