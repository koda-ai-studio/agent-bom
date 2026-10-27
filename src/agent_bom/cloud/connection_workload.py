"""Explicit, tenant-bound workload credential adapters for stored connections.

Only operators configure token files and trust audiences. API callers select an
opaque binding, which is revalidated on every use; there is no ambient fallback.
Provider token exchanges verify trust. Parsing configuration is not proof of
successful authentication or of read-only IAM grants.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from agent_bom.cloud.connection_broker import ConnectionBrokerError

_MODES = {"azure": {"managed_identity", "workload_identity"}, "gcp": {"workload_identity"}, "snowflake": {"workload_identity"}}
_READ_ONLY = "https://www.googleapis.com/auth/cloud-platform.read-only"


class WorkloadConnection(Protocol):
    """Connection fields consumed by the broker, independent of API storage."""

    @property
    def tenant_id(self) -> str: ...

    @property
    def provider(self) -> str: ...

    @property
    def auth_params(self) -> dict[str, Any]: ...

    @property
    def external_id_encrypted(self) -> str: ...

    @property
    def role_ref(self) -> str: ...

    @property
    def inventory_scope(self) -> str: ...


class SideScanGrant(BaseModel):
    """Operator-owned exact allowlists for snapshot lifecycle mutations."""

    model_config = ConfigDict(extra="forbid", strict=True)
    targets: list[str] = Field(min_length=1, max_length=256)
    collectors: list[str] = Field(min_length=1, max_length=256)
    locations: list[str] = Field(min_length=1, max_length=256)
    collector_resource_groups: list[str] = Field(default_factory=list, max_length=256)


class WorkloadBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tenant_id: str
    provider: Literal["azure", "gcp", "snowflake"]
    auth_mode: Literal["managed_identity", "workload_identity"]
    role_ref: str
    scope_id: str
    inventory_scope: Literal["account", "organization"] = "account"
    directory_tenant_id: str = ""
    token_file_path: str = ""
    audience: str = ""
    enabled: bool = True
    expires_at: str
    side_scan: SideScanGrant | None = None


def supported_workload_modes() -> dict[str, list[str]]:
    """Adapters usable in this deployment, not proof of configured bindings."""
    from agent_bom.cloud.snowflake_spcs_auth import native_app_mode

    return {provider: sorted(modes) for provider, modes in _MODES.items() if provider != "snowflake" or native_app_mode()}


def workload_mode(provider: str, params: dict[str, Any]) -> str:
    """Absent mode means legacy; an explicit unknown mode never falls back."""
    mode = str(params.get("auth_mode") or "")
    if mode and mode not in _MODES.get(provider, set()):
        raise ConnectionBrokerError("Unsupported connection authentication mode.")
    if not mode and params.get("credential_binding"):
        raise ConnectionBrokerError("Connection binding requires a workload authentication mode.")
    return mode


def resolve_binding(record: WorkloadConnection) -> WorkloadBinding:
    """Resolve fresh operator configuration and check every delegated boundary."""
    try:
        mode = workload_mode(record.provider, record.auth_params)
        ref = record.auth_params.get("credential_binding")
        configured = os.environ.get("AGENT_BOM_CONNECTION_WORKLOAD_BINDINGS_FILE", "")
        if not mode or not isinstance(ref, str) or not ref or not configured or record.external_id_encrypted:
            raise ValueError("invalid workload configuration")
        with Path(configured).open("rb") as stream:
            raw = stream.read(1_048_577)
        if len(raw) > 1_048_576:
            raise ValueError("oversize workload configuration")
        document = json.loads(raw)
        binding = WorkloadBinding.model_validate(document["bindings"][ref])
        expires = datetime.fromisoformat(binding.expires_at.replace("Z", "+00:00"))
        scope_key = {"azure": "subscription_id", "gcp": "project_id", "snowflake": "account"}[record.provider]
        if (
            not binding.enabled
            or expires.tzinfo is None
            or expires <= datetime.now(timezone.utc)
            or binding.tenant_id != record.tenant_id
            or binding.provider != record.provider
            or binding.auth_mode != mode
            or binding.role_ref != record.role_ref
            or not binding.scope_id
            or binding.scope_id != record.auth_params.get(scope_key)
            or binding.inventory_scope != record.inventory_scope
        ):
            raise ValueError("workload binding mismatch")
        if record.provider == "azure":
            if (
                not binding.directory_tenant_id
                or binding.directory_tenant_id != record.auth_params.get("tenant_id")
                or not binding.role_ref
            ):
                raise ValueError("directory mismatch")
            if binding.audience:
                raise ValueError("unexpected Azure audience")
        elif record.provider == "snowflake":
            from agent_bom.cloud.snowflake_spcs_auth import native_app_mode

            # Delegation must match this service's injected account. Callers may
            # not choose another user, role, warehouse, token file, or audience.
            if (
                not native_app_mode()
                or binding.scope_id != os.environ.get("SNOWFLAKE_ACCOUNT", "").strip()
                or binding.role_ref != binding.scope_id
                or binding.inventory_scope != "account"
                or binding.directory_tenant_id
                or binding.audience
                or binding.token_file_path
                or set(record.auth_params) - {"account", "auth_mode", "credential_binding", "inventory_scope"}
            ):
                raise ValueError("Snowflake workload binding mismatch")
        elif not re.fullmatch(
            r"//iam\.googleapis\.com/projects/[0-9]+/locations/global/workloadIdentityPools/[^/]+/providers/[^/]+", binding.audience
        ) or not re.fullmatch(r"[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com", binding.role_ref):
            raise ValueError("invalid Google trust target")
        if mode == "workload_identity" and record.provider != "snowflake" and not Path(binding.token_file_path).is_absolute():
            raise ValueError("workload token file must be operator configured")
        return binding
    except Exception as exc:
        raise ConnectionBrokerError("Workload connection binding is unavailable or does not match the connection.") from exc


def broker_workload(record: WorkloadConnection) -> Any:
    """Ordinary connection credentials always retain read-only Google scope."""
    return _broker_binding(resolve_binding(record), google_scope=_READ_ONLY)


def broker_side_scan_binding(binding: WorkloadBinding) -> Any:
    """Use an already authorized operator binding for its explicit lifecycle grant."""
    if binding.side_scan is None or binding.provider not in {"azure", "gcp"}:
        raise ConnectionBrokerError("Connection has no side-scan lifecycle grant.")
    return _broker_binding(binding, google_scope="https://www.googleapis.com/auth/cloud-platform")


def _broker_binding(binding: WorkloadBinding, *, google_scope: str) -> Any:
    try:
        if binding.provider == "azure":
            if binding.auth_mode == "managed_identity":
                from azure.identity import ManagedIdentityCredential

                return ManagedIdentityCredential(client_id=binding.role_ref)
            from azure.identity import WorkloadIdentityCredential

            return WorkloadIdentityCredential(
                tenant_id=binding.directory_tenant_id, client_id=binding.role_ref, token_file_path=binding.token_file_path
            )
        if binding.provider == "snowflake":
            import snowflake.connector

            from agent_bom.cloud.snowflake_spcs_auth import apply_spcs_workload_identity

            params: dict[str, Any] = {}
            if not apply_spcs_workload_identity(params) or params["account"] != binding.scope_id:
                raise ValueError("Snowflake workload context changed")
            return snowflake.connector.connect(**params)
        from google.auth import identity_pool, impersonated_credentials

        source = identity_pool.Credentials(
            audience=binding.audience,
            subject_token_type="urn:ietf:params:oauth:token-type:jwt",
            token_url="https://sts.googleapis.com/v1/token",
            credential_source={"file": binding.token_file_path},
            scopes=["https://www.googleapis.com/auth/iam"],
        )
        return impersonated_credentials.Credentials(
            source_credentials=source, target_principal=binding.role_ref, target_scopes=[google_scope], lifetime=3600
        )
    except Exception as exc:
        raise ConnectionBrokerError("Workload credential could not be constructed.") from exc
