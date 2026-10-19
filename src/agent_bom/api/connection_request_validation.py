"""Tenant connection request validation and safe response models."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Literal

from fastapi import HTTPException, Request
from pydantic import BaseModel

from agent_bom.api.connection_store import (
    INVENTORY_SCOPE_ACCOUNT,
    SCAN_MODE_FULL,
    VALID_INVENTORY_SCOPES,
    VALID_SCAN_MODES,
    CloudConnectionRecord,
    get_connection_store,
)
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.config import CONNECTIONS_SCHEDULER_MIN_INTERVAL_MINUTES

_MAX_AUTH_PARAMS = 20


_MAX_AUTH_PARAM_KEY_LEN = 64


_MAX_AUTH_PARAM_VALUE_LEN = 1024


_MAX_SCAN_INTERVAL_MINUTES = 7 * 24 * 60


_REGION_RE = re.compile(r"[a-z]{2}(-gov)?-[a-z]+-\d{1,2}")


_MAX_REGIONS = 50


class CloudConnectionScanAccepted(BaseModel):
    """Stable handoff returned after a connection scan is durably queued."""

    schema_version: Literal["cloud.connections.scan.accepted.v1"] = "cloud.connections.scan.accepted.v1"
    connection_id: str
    tenant_id: str
    provider: str
    job_id: str
    status: Literal["pending"] = "pending"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tenant(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "system"


def _validate_scan_interval(interval: int | None) -> int | None:
    """Validate a recurring scan interval (minutes).

    Null is allowed (manual-only). A set value must be at least the configured
    minimum so the scheduler never hammers a customer account, and at most one
    week so a typo cannot silently park a connection.
    """
    if interval is None:
        return None
    if interval < CONNECTIONS_SCHEDULER_MIN_INTERVAL_MINUTES:
        raise HTTPException(
            status_code=400,
            detail=f"scan_interval_minutes must be at least {CONNECTIONS_SCHEDULER_MIN_INTERVAL_MINUTES} minutes.",
        )
    if interval > _MAX_SCAN_INTERVAL_MINUTES:
        raise HTTPException(
            status_code=400,
            detail=f"scan_interval_minutes must be at most {_MAX_SCAN_INTERVAL_MINUTES} minutes.",
        )
    return interval


def _validate_auth_params(provider: str, auth_params: dict[str, str]) -> dict[str, str]:
    """Validate the non-secret provider params blob (bounds + string coercion).

    Only declared provider metadata is accepted. Unknown fields and recognizable
    credential payloads fail closed without echoing keys or values.
    """
    from agent_bom.cloud.connection_metadata import public_connection_param

    if not auth_params:
        return {}
    if len(auth_params) > _MAX_AUTH_PARAMS:
        raise HTTPException(status_code=400, detail=f"Too many auth_params (max {_MAX_AUTH_PARAMS}).")
    cleaned: dict[str, str] = {}
    for key, value in auth_params.items():
        key_str = str(key).strip()
        if not key_str:
            continue
        if len(key_str) > _MAX_AUTH_PARAM_KEY_LEN:
            raise HTTPException(status_code=400, detail=f"auth_params key too long (max {_MAX_AUTH_PARAM_KEY_LEN}).")
        value_str = str(value).strip()
        if len(value_str) > _MAX_AUTH_PARAM_VALUE_LEN:
            raise HTTPException(status_code=400, detail=f"auth_params value too long (max {_MAX_AUTH_PARAM_VALUE_LEN}).")
        if not public_connection_param(provider, key_str, value_str):
            raise HTTPException(status_code=400, detail="Invalid public connection metadata; use the credential field for secrets.")
        cleaned[key_str] = value_str
    return cleaned


def _validate_inventory_scope(scope: str | None, *, auth_params: dict[str, str] | None = None) -> str:
    """Resolve the stored inventory scope; the column is the single authority.

    An explicit body value wins. When the body omits the field, a legacy
    ``auth_params["inventory_scope"]`` is consumed as the intent — popped from
    the blob so the resolved value lives only in the column and can later be
    turned off by an update. A legacy value that is not a known scope narrows to
    the ``account`` default (fail closed) rather than rejecting the request; the
    response reports the scope that was actually stored.
    """
    raw = str(scope or "").strip().lower()
    if auth_params is not None:
        legacy = str(auth_params.pop("inventory_scope", "") or "").strip().lower()
        if not raw and legacy in VALID_INVENTORY_SCOPES:
            raw = legacy
    if not raw:
        return INVENTORY_SCOPE_ACCOUNT
    if raw not in VALID_INVENTORY_SCOPES:
        raise HTTPException(
            status_code=400,
            detail=f"inventory_scope must be one of: {', '.join(VALID_INVENTORY_SCOPES)}.",
        )
    return raw


def _validate_scan_mode(mode: str | None) -> str:
    """Normalize scan_mode to full|continuous."""
    raw = str(mode or "").strip().lower()
    if not raw:
        return SCAN_MODE_FULL
    if raw not in VALID_SCAN_MODES:
        raise HTTPException(
            status_code=400,
            detail=f"scan_mode must be one of: {', '.join(VALID_SCAN_MODES)}.",
        )
    return raw


def _validate_regions(regions: list[str]) -> list[str]:
    from agent_bom.cloud.aws_inventory import ALL_REGIONS_SENTINEL

    cleaned = [r.strip() for r in regions if r.strip()]
    # Explicit "All regions" affordance: the sentinel resolves to an estate-wide
    # multi-region scan. It is exclusive — never mixed with specific regions —
    # and normalized to lowercase so the scan dispatch can detect it reliably.
    if any(r.lower() == ALL_REGIONS_SENTINEL for r in cleaned):
        if len(cleaned) > 1:
            raise HTTPException(
                status_code=400,
                detail="'all' regions is exclusive — do not combine it with specific regions.",
            )
        return [ALL_REGIONS_SENTINEL]
    if len(cleaned) > _MAX_REGIONS:
        raise HTTPException(status_code=400, detail=f"Too many regions (max {_MAX_REGIONS}).")
    for region in cleaned:
        if not _REGION_RE.fullmatch(region):
            raise HTTPException(status_code=400, detail=f"Invalid region format: {region}")
    return cleaned


def _require_connection(request: Request, connection_id: str) -> CloudConnectionRecord:
    tenant_id = _tenant(request)
    record = get_connection_store().get(tenant_id, connection_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Connection {connection_id} not found")
    return record


def _reject_showcase_connection(record: CloudConnectionRecord) -> None:
    """Keep synthetic demo rows from entering a real credential or scan path."""
    if record.auth_params.get("demo") is True:
        raise HTTPException(
            status_code=409,
            detail="Showcase connections are synthetic and cannot run connection tests or scans.",
        )
