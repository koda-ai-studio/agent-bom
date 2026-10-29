"""Response models for the gateway live feed routes."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from agent_bom.api.gateway_activity_store import GatewayActivityRecord
from agent_bom.api.proxy_provenance import ProducerAssurance


class GatewayFeedLedgerUnavailableError(RuntimeError):
    """The shared ledger cannot satisfy a cursor-backed read."""


class GatewayActivityStreamPage(BaseModel):
    """One atomic SSE data frame; its SSE id is the next ledger cursor.

    Canonical records include profile/enforcement outcomes omitted by the
    legacy dashboard projection. No process-local alerts or cost spans are
    mixed into this ordered, resumable contract.
    """

    schema_version: Literal["gateway.activity.stream.v1"] = "gateway.activity.stream.v1"
    source: Literal["gateway_activity_ledger"] = "gateway_activity_ledger"
    scope: Literal["canonical_gateway_activity"] = "canonical_gateway_activity"
    tenant_id: str
    events: list[GatewayActivityRecord]
    next_cursor: str
    has_more: bool
    retention_floor_ordinal: int = Field(ge=1)
    latest_ordinal: int = Field(ge=0)
    max_events_per_tenant: int = Field(ge=1)
    dedupe_window_events: int = Field(ge=1)


class ProducerAssuranceCountsModel(BaseModel):
    unknown: int = Field(default=0, ge=0)
    caller_asserted: int = Field(default=0, ge=0)


class GatewayFeedHealthModel(BaseModel):
    assurance_basis: Literal["transport_receipt"] = "transport_receipt"
    producer_assurance: ProducerAssurance = "unknown"
    state: Literal["live", "stale", "unavailable", "sample"]
    live: bool
    heartbeat_at: str | None
    age_seconds: int | None
    stale_after_seconds: int
    reason: str


class GatewayFeedEventModel(BaseModel):
    producer_assurance: ProducerAssurance = "unknown"
    event_id: str
    decision_id: str = Field(default="", max_length=200)
    ts: str
    agent: str
    identity_id: str = Field(default="", max_length=200)
    profile_id: str = Field(default="", max_length=200)
    profile_revision: int = Field(default=0, ge=0)
    blueprint_id: str = Field(default="", max_length=200)
    blueprint_revision: int = Field(default=0, ge=0)
    policy_ids: list[str] = Field(default_factory=list, max_length=200)
    reason_code: str = Field(default="", max_length=200)
    development_mode: bool = False
    action_type: Literal[
        "tool_call_authorized",
        "tool_call_blocked",
        "data_filter_applied",
        "llm_call",
    ]
    target: str
    upstream: str
    decision: str
    data_action: str
    policy_source: str
    trace_id: str
    detail: str
    tenant: str
    shadow: bool
    source: str
    ingest_ordinal: int | None = Field(default=None, ge=1)
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None


class GatewayFeedCompletenessModel(BaseModel):
    status: Literal["complete", "partial"]
    reasons: list[str]
    server_ordered: bool
    retention_floor_ordinal: int = Field(ge=1)
    latest_ordinal: int = Field(ge=0)
    max_events_per_tenant: int = Field(ge=0)
    dedupe_window_events: int = Field(ge=0)


class GatewayFeedKpiCompletenessModel(BaseModel):
    status: Literal["complete", "partial"]
    reasons: list[str]
    retention_floor_ordinal: int = Field(ge=1)
    latest_ordinal: int = Field(ge=0)


class GatewayFeedWindowModel(BaseModel):
    start: str
    end: str
    timezone: Literal["UTC"]
    exact: bool


class GatewayFeedResponseModel(BaseModel):
    producer_assurance: ProducerAssurance = "unknown"
    producer_assurance_counts: ProducerAssuranceCountsModel = Field(default_factory=ProducerAssuranceCountsModel)
    producer_assurance_count_basis: Literal["classified_events"] = "classified_events"
    schema_version: str
    tenant_id: str
    generated_at: str
    count: int
    events: list[GatewayFeedEventModel]
    next_cursor: str | None
    has_more: bool
    source: Literal["gateway_activity_ledger", "degraded_single_process"]
    completeness: GatewayFeedCompletenessModel
    health: GatewayFeedHealthModel


class GatewayFeedKpisModel(BaseModel):
    producer_assurance: ProducerAssurance = "unknown"
    producer_assurance_counts: ProducerAssuranceCountsModel = Field(default_factory=ProducerAssuranceCountsModel)
    producer_assurance_count_basis: Literal["classified_events"] = "classified_events"
    schema_version: str
    tenant_id: str
    generated_at: str
    calls_today: int
    blocked_today: int
    shadow_ai_blocked: int
    data_filters_applied: int
    tool_calls_authorized: int
    llm_calls: int
    uptime_seconds: float | None = None
    source: Literal["gateway_activity_ledger", "degraded_single_process"]
    completeness: GatewayFeedKpiCompletenessModel
    window: GatewayFeedWindowModel
    health: GatewayFeedHealthModel
