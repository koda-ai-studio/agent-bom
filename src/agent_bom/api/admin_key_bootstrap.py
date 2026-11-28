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
from agent_bom.api.auth import Role, create_api_key, get_key_store, key_store_is_durable
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

    store = get_key_store()
    if not key_store_is_durable(store) and not allow_inmemory:
        raise RuntimeError(
            "A persistent key store (AGENT_BOM_POSTGRES_URL or AGENT_BOM_DB) is required for hosted admin bootstrap; "
            "use --allow-inmemory only for local tests."
        )
    raw_key, record = create_api_key(
        name=name,
        role=Role.ADMIN,
        expires_at=expires_at,
        scopes=scopes or ["*"],
        tenant_id=tenant_id,
    )
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


def _reserve_raw_key_file(path: Path, *, force: bool) -> tuple[Path, Path, int]:
    """Open a private file before any key exists, so a refused path never strands a minted key.

    Returns ``(final, staging, fd)``. Without ``force`` the final path is created
    exclusively; with ``force`` a private sibling is staged and only replaces the
    existing file once the key is written, so a failed mint keeps the old key file.
    """
    final = path.expanduser()
    final.parent.mkdir(parents=True, exist_ok=True)
    if not force and final.exists():
        raise RuntimeError(f"{RAW_KEY_FILE_EXISTS} {final}")
    staging = final.with_name(f".{final.name}.{os.getpid()}.tmp") if force else final
    try:
        return final, staging, os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise RuntimeError(f"{RAW_KEY_FILE_EXISTS} {staging}") from exc


def _write_reserved(final: Path, staging: Path, fd: int, raw_key: str) -> Path:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(raw_key)
        handle.write("\n")
    staging.chmod(0o600)
    if staging != final:
        os.replace(staging, final)
    return final


def write_raw_key_file(path: Path, raw_key: str, *, force: bool = False) -> Path:
    """Write the one-time raw API key to a private file without logging it."""
    final, staging, fd = _reserve_raw_key_file(path, force=force)
    return _write_reserved(final, staging, fd, raw_key)


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

    final, staging, fd = _reserve_raw_key_file(raw_key_file, force=force)
    try:
        minted = mint_admin_key(tenant_id=tenant_id, name=name, expires_at=expires_at, scopes=scopes, allow_inmemory=allow_inmemory)
    except BaseException:
        os.close(fd)
        staging.unlink(missing_ok=True)
        raise
    written = _write_reserved(final, staging, fd, minted.raw_key)
    return {**minted.metadata, "raw_key_file": str(written)}


def failure_message(exc: Exception) -> str:
    """Operator-facing failure text that never echoes key material or internals."""

    if isinstance(exc, RuntimeError) and str(exc).startswith(RAW_KEY_FILE_EXISTS):
        return f"failed to mint hosted admin key: {exc}"
    return "failed to mint hosted admin key; check server logs and bootstrap configuration"
