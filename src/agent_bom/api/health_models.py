"""Health models for the public API."""

from __future__ import annotations

from pydantic import BaseModel, Field


class VersionInfo(BaseModel):
    version: str
    api_version: str = "v1"
    python_package: str = "agent-bom"


class TracingHealth(BaseModel):
    w3c_trace_context: bool = True
    w3c_tracestate: bool = True
    w3c_baggage: bool = True
    otlp_export: str = "disabled"
    otlp_endpoint_configured: bool = False
    otlp_headers_configured: bool = False
    # Audit-event OTLP *log* export (governance chain → OTLP logs), distinct from
    # the trace-span export above.
    otlp_logs_export: str = "disabled"
    otlp_logs_endpoint_configured: bool = False
    otlp_logs_headers_configured: bool = False


class AnalyticsHealth(BaseModel):
    backend: str = "disabled"
    enabled: bool = False
    buffered: bool = False
    clickhouse_url_configured: bool = False
    flush_interval_seconds: float | None = None
    max_batch: int | None = None
    queue_capacity: int | None = None
    queue_depth: int | None = None
    dropped_count: int | None = None


class PostgresPortabilityHealth(BaseModel):
    """Non-secret, operator-declared PostgreSQL compatibility posture."""

    provider: str
    declared_hint: str
    contract: str = "postgresql"
    evidence: str = "provider_unverified"
    next_action: str | None = "agent-bom doctor"


class StorageHealth(BaseModel):
    control_plane_backend: str = "inmemory"
    job_store: str = "inmemory"
    fleet_store: str = "inmemory"
    policy_store: str = "inmemory"
    source_store: str = "inmemory"
    credential_ref_store: str = "inmemory"
    schedule_store: str = "inmemory"
    exception_store: str = "inmemory"
    trend_store: str = "inmemory"
    graph_store: str = "inmemory"
    key_store: str = "inmemory"
    audit_log: str = "inmemory"
    postgres: PostgresPortabilityHealth | None = None


class EntitlementHealth(BaseModel):
    status: str = "missing"
    lane: str = "oss"
    support_tier: str = "community"
    enabled_feature_count: int = 0
    metadata_only: bool = True
    current_oss_paths_gated: bool = False


class PublicHealthResponse(BaseModel):
    """Non-sensitive liveness and UI bootstrap posture."""

    status: str = "ok"
    version: str
    auth_required: bool = True
    auth_configured: bool = False
    configured_auth_modes: list[str] = Field(default_factory=list)
    unauthenticated_allowed: bool = False


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    auth_required: bool = True
    auth_configured: bool = False
    configured_auth_modes: list[str] = Field(default_factory=list)
    unauthenticated_allowed: bool = False
    # Read-only packaging honesty: recurring connection intervals only fire when
    # AGENT_BOM_CONNECTIONS_SCHEDULER (or Helm controlPlane.connectionsScheduler)
    # is enabled. Default false so self-hosted installs do not silently claim cadence.
    connections_scheduler_enabled: bool = False
    tracing: TracingHealth
    analytics: AnalyticsHealth
    storage: StorageHealth
    entitlements: EntitlementHealth = Field(default_factory=EntitlementHealth)
