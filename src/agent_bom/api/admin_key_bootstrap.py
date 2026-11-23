"""Mint the first admin API key of a self-hosted control plane.

The raw key is written once to a local 0600 file, never logged. The stored
record goes through the same key store the API process reads, so hosted
deployments run this inside the API container with ``AGENT_BOM_POSTGRES_URL``
configured (``agent-bom auth mint-admin-key``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_bom.api.api_key_record import TenantNotProvisionedError
from agent_bom.api.auth import Role, create_api_key, get_key_store
from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

RAW_KEY_FILE_EXISTS = "raw key file already exists:"


@dataclass(frozen=True)
class MintedAdminKey:
    """One-time key material plus non-secret metadata for operator output."""

    raw_key: str
    metadata: dict[str, Any]


def mint_admin_key(
    *,
    tenant_id: str,
    name: str,
    expires_at: str | None = None,
    scopes: list[str] | None = None,
    allow_inmemory: bool = False,
) -> MintedAdminKey:
    """Create and persist one admin key for an invite-only hosted instance."""

    if not os.environ.get("AGENT_BOM_POSTGRES_URL") and not allow_inmemory:
        raise RuntimeError("AGENT_BOM_POSTGRES_URL must be set for hosted admin bootstrap; use --allow-inmemory only for local tests.")
    raw_key, record = create_api_key(
        name=name,
        role=Role.ADMIN,
        expires_at=expires_at,
        scopes=scopes or ["*"],
        tenant_id=tenant_id,
    )
    store = get_key_store()
    # Tenant-scoped stores authorize the write against the bound tenant (row-level
    # security), and a fresh database has no row for it yet: create the tenant and
    # its first key together, as tenant invitations do.
    token = set_current_tenant(tenant_id)
    try:
        try:
            store.add(record)
        except TenantNotProvisionedError:
            store.provision_tenant_key(record, team_name=tenant_id)
    finally:
        reset_current_tenant(token)
    return MintedAdminKey(
        raw_key=raw_key,
        metadata={
            "key_id": record.key_id,
            "key_prefix": record.key_prefix,
            "name": record.name,
            "role": record.role.value,
            "tenant_id": record.tenant_id,
            "expires_at": record.expires_at,
            "scopes": record.scopes,
        },
    )


def write_raw_key_file(path: Path, raw_key: str, *, force: bool = False) -> Path:
    """Write the one-time raw API key to a private file without logging it."""

    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_TRUNC if force else os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise RuntimeError(f"{RAW_KEY_FILE_EXISTS} {path}") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(raw_key)
        handle.write("\n")
    path.chmod(0o600)
    return path


def bootstrap_admin_key(
    *,
    tenant_id: str,
    name: str,
    raw_key_file: Path,
    expires_at: str | None = None,
    scopes: list[str] | None = None,
    allow_inmemory: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    """Mint, write the raw key file, and return the non-secret metadata to print."""

    minted = mint_admin_key(tenant_id=tenant_id, name=name, expires_at=expires_at, scopes=scopes, allow_inmemory=allow_inmemory)
    written = write_raw_key_file(raw_key_file, minted.raw_key, force=force)
    return {**minted.metadata, "raw_key_file": str(written)}


def failure_message(exc: Exception) -> str:
    """Operator-facing failure text that never echoes key material or internals."""

    if isinstance(exc, RuntimeError) and str(exc).startswith(RAW_KEY_FILE_EXISTS):
        return f"failed to mint hosted admin key: {exc}"
    return "failed to mint hosted admin key; check server logs and bootstrap configuration"
