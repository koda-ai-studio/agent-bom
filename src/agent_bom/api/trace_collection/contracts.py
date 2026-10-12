"""Internal checkpoints and credential-free public collection receipts."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

PAGE_LIMIT = 100
LEASE_SECONDS = 60
OVERLAP_SECONDS = 1800
SAFETY_DELAY_SECONDS = 900
MAX_WINDOW_SECONDS = 86400
MAX_RECEIPTS = 100_000


class CollectionConflictError(RuntimeError):
    """Collection cannot safely advance; no checkpoint is discarded."""


class CollectionState(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope_digest: str
    window_start: str
    window_end: str
    cursor: str | None = None
    owner: str = ""
    lease_until: float = 0
    retry_after: float = 0
    completed_until: str | None = None
    last_success: str | None = None
    persisted: int = 0
    pages: int = 0
    consecutive_failures: int = 0
    last_error: str | None = None
    cursor_history: list[str] = Field(default_factory=list)
    status: Literal["collecting", "partial", "caught_up", "failed"] = "partial"


class CollectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    connection_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")


class CollectionReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["trace.collection.v1"] = "trace.collection.v1"
    connection_id: str
    provider: Literal["langfuse"] = "langfuse"
    status: Literal["not_started", "collecting", "partial", "caught_up", "failed"]
    persisted: int = 0
    pages: int = 0
    window_start: str | None = None
    window_end: str | None = None
    completed_until: str | None = None
    last_success: str | None = None
    lag_seconds: float | None = None
    retry_after_seconds: int = 0
    consecutive_failures: int = 0
    last_error: str | None = None
    coverage: Literal["bounded_window"] = "bounded_window"
    raw_payload_stored: Literal[False] = False


def receipt(connection_id: str, state: CollectionState | None, now: float) -> CollectionReceipt:
    if state is None:
        return CollectionReceipt(connection_id=connection_id, status="not_started")
    values = state.model_dump(exclude={"scope_digest", "cursor", "owner", "lease_until", "retry_after", "cursor_history"})
    lag = max(0, now - datetime.fromisoformat(state.completed_until).timestamp()) if state.completed_until else None
    return CollectionReceipt(
        connection_id=connection_id,
        **values,
        lag_seconds=lag,
        retry_after_seconds=max(0, int(max(state.retry_after, state.lease_until) - now + 0.999)),
    )
