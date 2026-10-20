"""Source models for the public API."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SourceKind(str, Enum):
    SCAN_REPO = "scan.repo"
    SCAN_IMAGE = "scan.image"
    SCAN_IAC = "scan.iac"
    SCAN_CLOUD = "scan.cloud"
    SCAN_MCP_CONFIG = "scan.mcp_config"
    CONNECTOR_CLOUD_READ_ONLY = "connector.cloud_read_only"
    CONNECTOR_REGISTRY = "connector.registry"
    CONNECTOR_WAREHOUSE = "connector.warehouse"
    INGEST_FLEET_SYNC = "ingest.fleet_sync"
    INGEST_TRACE_PUSH = "ingest.trace_push"
    INGEST_RESULT_PUSH = "ingest.result_push"
    INGEST_ARTIFACT_IMPORT = "ingest.artifact_import"
    RUNTIME_PROXY = "runtime.proxy"
    RUNTIME_GATEWAY = "runtime.gateway"


class SourceStatus(str, Enum):
    CONFIGURED = "configured"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DISABLED = "disabled"


class SourceCredentialMode(str, Enum):
    """How a source's credential metadata is represented.

    Older clients used ``credential_ref`` as the mode spelling. Normalize it
    to the canonical reference mode so it cannot bypass the reference-presence
    and execution checks in the source routes.
    """

    NONE = "none"
    REFERENCE = "reference"

    @classmethod
    def _missing_(cls, value: object) -> "SourceCredentialMode | None":
        if not isinstance(value, str):
            return None
        normalized = value.strip().lower().replace("-", "_")
        if normalized in {"credential_ref", cls.REFERENCE.value}:
            return cls.REFERENCE
        if normalized == cls.NONE.value:
            return cls.NONE
        return None


class CredentialRefStatus(str, Enum):
    CONFIGURED = "configured"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DISABLED = "disabled"
    RETIRED = "retired"


class CredentialRefRecord(BaseModel):
    credential_ref_id: str
    tenant_id: str = "default"
    display_name: str
    provider: str
    mode: str = "external_ref"
    external_ref: str | None
    description: str = ""
    owner: str = ""
    scopes: list[str] = Field(default_factory=list)
    credential_class: str = "generic"
    last_rotated_at: str | None = None
    expires_at: str | None = None
    rotation_interval_days: int | None = Field(default=None, ge=1)
    max_age_days: int | None = Field(default=None, ge=1)
    expiry_warning_days: int | None = Field(default=None, ge=1)
    enabled: bool = True
    status: CredentialRefStatus = CredentialRefStatus.CONFIGURED
    last_validated_at: str | None = None
    last_validation_status: str | None = None
    last_validation_message: str | None = None
    created_at: str = ""
    updated_at: str = ""


class CredentialRefCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str
    provider: str
    mode: str = "external_ref"
    external_ref: str
    description: str = ""
    owner: str = ""
    scopes: list[str] = Field(default_factory=list)
    credential_class: str = "generic"
    last_rotated_at: str | None = None
    expires_at: str | None = None
    rotation_interval_days: int | None = Field(default=None, ge=1)
    max_age_days: int | None = Field(default=None, ge=1)
    expiry_warning_days: int | None = Field(default=None, ge=1)
    enabled: bool = True
    tenant_id: str = "default"


class CredentialRefUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str | None = None
    provider: str | None = None
    mode: str | None = None
    external_ref: str | None = None
    description: str | None = None
    owner: str | None = None
    scopes: list[str] | None = None
    credential_class: str | None = None
    last_rotated_at: str | None = None
    expires_at: str | None = None
    rotation_interval_days: int | None = Field(default=None, ge=1)
    max_age_days: int | None = Field(default=None, ge=1)
    expiry_warning_days: int | None = Field(default=None, ge=1)
    enabled: bool | None = None
    status: CredentialRefStatus | None = None


class SourceRecord(BaseModel):
    source_id: str
    tenant_id: str = "default"
    display_name: str
    kind: SourceKind
    description: str = ""
    owner: str = ""
    connector_name: str | None = None
    credential_mode: SourceCredentialMode = SourceCredentialMode.NONE
    credential_ref: str | None = None
    enabled: bool = True
    status: SourceStatus = SourceStatus.CONFIGURED
    config: dict[str, Any] = Field(default_factory=dict)
    last_tested_at: str | None = None
    last_test_status: str | None = None
    last_test_message: str | None = None
    last_run_at: str | None = None
    last_run_status: str | None = None
    last_job_id: str | None = None
    created_at: str = ""
    updated_at: str = ""


class SourceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str
    kind: SourceKind
    description: str = ""
    owner: str = ""
    connector_name: str | None = None
    credential_mode: SourceCredentialMode = SourceCredentialMode.NONE
    credential_ref: str | None = None
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    tenant_id: str = "default"


class SourceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str | None = None
    description: str | None = None
    owner: str | None = None
    connector_name: str | None = None
    credential_mode: SourceCredentialMode | None = None
    credential_ref: str | None = None
    enabled: bool | None = None
    status: SourceStatus | None = None
    config: dict[str, Any] | None = None


class SourceCohortRunRequest(BaseModel):
    """Exact registered sources to scan and correlate as one immutable cohort."""

    model_config = ConfigDict(extra="forbid")

    source_ids: list[str] = Field(min_length=2, max_length=32)
    max_age_hours: int = Field(default=168, ge=1, le=8760)

    @field_validator("source_ids")
    @classmethod
    def normalize_source_ids(cls, values: list[str]) -> list[str]:
        normalized = sorted(value.strip() for value in values)
        if any(not value for value in normalized):
            raise ValueError("source_ids cannot contain empty values")
        if len(set(normalized)) != len(normalized):
            raise ValueError("source_ids must be distinct")
        return normalized
