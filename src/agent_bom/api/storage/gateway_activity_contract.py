"""Typed records, errors and protocol for the tenant-scoped gateway ledger."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Protocol

from agent_bom.api.proxy_provenance import GatewaySubmissionProvenance, ProducerAssurance
from agent_bom.api.storage.gateway_activity_window import GatewayActivityWindowSummary


class GatewayActivityConflictError(ValueError):
    """An event ID was replayed with different canonical metadata."""


class GatewayActivityCursorError(ValueError):
    """A cursor is malformed, foreign, unsupported, or ahead of the ledger."""


class GatewayActivityCursorExpiredError(GatewayActivityCursorError):
    """A cursor points below the retained tenant activity floor."""

    def __init__(self, retention_floor_ordinal: int) -> None:
        super().__init__("Gateway activity cursor is older than retained history")
        self.retention_floor_ordinal = retention_floor_ordinal


@dataclass(frozen=True)
class GatewayActivityRecord:
    tenant_id: str
    event_id: str
    decision_id: str
    event_type: str
    event_schema_version: str
    event_timestamp: str
    ingested_at: str
    source_id: str
    session_id: str
    agent_id: str
    upstream: str
    tool: str
    decision: str
    policy_source: str
    trace_id: str
    identity_id: str = ""
    profile_id: str = ""
    profile_revision: int = 0
    blueprint_id: str = ""
    blueprint_revision: int = 0
    policy_ids: tuple[str, ...] = ()
    reason_code: str = ""
    data_action: str = ""
    policy_id: str = ""
    evidence_id: str = ""
    development_mode: bool = False
    event_digest: str = ""
    ingest_ordinal: int = 0
    raw_payload_stored: bool = False
    record_schema_version: str = "gateway.activity.record.v1"
    submission_provenance: GatewaySubmissionProvenance | None = None
    receipt_trace_id: str = ""

    def __post_init__(self) -> None:
        if self.record_schema_version == "gateway.activity.record.v1":
            if self.submission_provenance is not None:
                raise ValueError("legacy gateway activity cannot carry new provenance")
        elif self.record_schema_version == "gateway.activity.record.v2":
            provenance = self.submission_provenance
            if not isinstance(provenance, GatewaySubmissionProvenance):
                raise ValueError("gateway activity v2 requires typed submission provenance")
            provenance = GatewaySubmissionProvenance.model_validate(provenance)
            object.__setattr__(self, "submission_provenance", provenance)
            if provenance.submission_source_id != self.source_id or provenance.submission_session_id != self.session_id:
                raise ValueError("gateway activity submission context does not match provenance")
        else:
            raise ValueError("unsupported gateway activity record schema")

    @property
    def producer_assurance(self) -> ProducerAssurance:
        return self.submission_provenance.producer_assurance if self.submission_provenance else "unknown"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["policy_ids"] = list(self.policy_ids)
        if not self.receipt_trace_id:
            payload.pop("receipt_trace_id", None)
        if self.submission_provenance is None:
            # Preserve historical v1 serialization and event digests exactly.
            payload.pop("submission_provenance", None)
        else:
            payload["submission_provenance"] = self.submission_provenance.model_dump()
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True)
class GatewayActivityAppendResult:
    inserted_event_ids: tuple[str, ...] = ()
    duplicate_event_ids: tuple[str, ...] = ()

    @property
    def inserted_count(self) -> int:
        return len(self.inserted_event_ids)

    @property
    def duplicate_count(self) -> int:
        return len(self.duplicate_event_ids)


@dataclass(frozen=True)
class GatewayActivityPage:
    tenant_id: str
    events: list[dict[str, Any]]
    cursor: str | None
    next_cursor: str | None
    has_more: bool
    retention_floor_ordinal: int
    latest_ordinal: int
    max_events_per_tenant: int
    dedupe_window_events: int


class GatewayActivityStore(Protocol):
    """Shared contract for the tenant-scoped gateway activity ledger."""

    max_events_per_tenant: int
    max_tombstones_per_tenant: int

    def init_schema(self) -> None: ...

    def append_batch(self, records: list[GatewayActivityRecord]) -> GatewayActivityAppendResult: ...

    def list_activity(
        self,
        tenant_id: str,
        *,
        cursor: str | None = None,
        limit: int = 100,
    ) -> GatewayActivityPage: ...

    def window_activity(self, tenant_id: str, **kwargs: Any) -> list[GatewayActivityRecord]: ...

    def encode_cursor(self, tenant_id: str, ordinal: int) -> str: ...

    def summarize_window(self, tenant_id: str, *, start: str, end: str) -> GatewayActivityWindowSummary: ...
