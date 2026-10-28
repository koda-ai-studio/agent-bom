"""Tenant-bound Postgres delivery leases; stale owners cannot acknowledge work."""

from __future__ import annotations

import hashlib
import json
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

from agent_bom.api.postgres_common import _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.storage_schema import ensure_postgres_schema_version
from agent_bom.api.tenant_worker import tenant_bound_context
from agent_bom.core.tenancy import require_explicit_tenant_id
from agent_bom.security import sanitize_sensitive_payload

DELIVERY_DDL = """
CREATE TABLE IF NOT EXISTS gateway_audit_outbox (
    tenant_id TEXT NOT NULL,
    stream_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    digest TEXT NOT NULL,
    payload TEXT NOT NULL,
    payload_bytes INTEGER NOT NULL CHECK (payload_bytes > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_token TEXT,
    lease_until TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, stream_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_gateway_audit_outbox_claim
    ON gateway_audit_outbox(tenant_id, stream_id, created_at, event_id);
"""


@dataclass(frozen=True)
class DeliveryLease:
    token: str
    events: list[dict[str, Any]]


class PostgresGatewayOutbox:
    """Bounded queue for one tenant and destination, with database-clock leases.

    Delivery is at least once. The receiving ledger must deduplicate event IDs.
    Credentials are never persisted. Every operation binds RLS explicitly.
    """

    def __init__(
        self, tenant_id: str, stream_id: str, *, pool: Any = None, max_bytes: int = 8 * 1024 * 1024, lease_seconds: int = 60
    ) -> None:
        self.tenant_id = require_explicit_tenant_id(tenant_id)
        if not stream_id or len(stream_id) > 200 or not 1 <= max_bytes <= 64 * 1024 * 1024 or not 1 <= lease_seconds <= 300:
            raise ValueError("Invalid gateway delivery bounds")
        self.stream_id, self.max_bytes, self.lease_seconds = stream_id, max_bytes, lease_seconds
        self.pool = pool or _get_pool()
        with self.pool.connection() as conn:
            if ensure_postgres_schema_version(conn, "gateway_audit_outbox", version=1):
                conn.execute(DELIVERY_DDL)
                _ensure_tenant_rls(conn, "gateway_audit_outbox", "tenant_id")
                conn.commit()

    @contextmanager
    def connection(self) -> Iterator[Any]:
        with tenant_bound_context(self.tenant_id), _tenant_connection(self.pool) as conn:
            yield conn

    def enqueue(self, event: dict[str, Any]) -> str:
        if event.get("tenant_id") != self.tenant_id:
            raise ValueError("Gateway delivery tenant mismatch")
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not 1 <= len(event_id) <= 200:
            raise ValueError("Invalid gateway delivery event identity")
        payload = json.dumps(sanitize_sensitive_payload(event), sort_keys=True, separators=(",", ":"))
        size = len(payload.encode("utf-8"))
        if size > min(self.max_bytes, 65536):
            raise ValueError("Gateway audit event exceeds delivery budget")
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        with self.connection() as conn:
            # Serialize admission, not network delivery, so concurrent pods cannot
            # collectively exceed the configured destination queue budget.
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (json.dumps([self.tenant_id, self.stream_id]),))
            existing = conn.execute(
                "SELECT digest FROM gateway_audit_outbox WHERE tenant_id=%s AND stream_id=%s AND event_id=%s",
                (self.tenant_id, self.stream_id, event_id),
            ).fetchone()
            if existing:
                if existing[0] != digest:
                    raise ValueError("Gateway audit event identity conflict")
                return event_id
            used, count = conn.execute(
                "SELECT COALESCE(SUM(payload_bytes),0),COUNT(*) FROM gateway_audit_outbox WHERE tenant_id=%s AND stream_id=%s",
                (self.tenant_id, self.stream_id),
            ).fetchone()
            if used + size > self.max_bytes or count >= 10000:
                raise ValueError("Gateway audit backlog is full")
            conn.execute(
                "INSERT INTO gateway_audit_outbox(tenant_id,stream_id,event_id,digest,payload,payload_bytes) VALUES(%s,%s,%s,%s,%s,%s)",
                (self.tenant_id, self.stream_id, event_id, digest, payload, size),
            )
            conn.commit()
        return event_id

    def claim(self, limit: int = 100) -> DeliveryLease | None:
        if not 1 <= limit <= 500:
            raise ValueError("Invalid gateway delivery batch size")
        token = uuid.uuid4().hex
        with self.connection() as conn:
            rows = conn.execute(
                "WITH picked AS (SELECT event_id FROM gateway_audit_outbox "
                "WHERE tenant_id=%s AND stream_id=%s AND (lease_until IS NULL OR lease_until <= clock_timestamp()) "
                "ORDER BY created_at,event_id LIMIT %s FOR UPDATE SKIP LOCKED) "
                "UPDATE gateway_audit_outbox q SET lease_token=%s,lease_until=clock_timestamp() + (%s * interval '1 second') "
                "FROM picked WHERE q.tenant_id=%s AND q.stream_id=%s AND q.event_id=picked.event_id RETURNING q.payload",
                (self.tenant_id, self.stream_id, limit, token, self.lease_seconds, self.tenant_id, self.stream_id),
            ).fetchall()
            conn.commit()
        return DeliveryLease(token, [json.loads(row[0]) for row in rows]) if rows else None

    def acknowledge(self, lease: DeliveryLease) -> bool:
        with self.connection() as conn:
            deleted = conn.execute(
                "DELETE FROM gateway_audit_outbox WHERE tenant_id=%s AND stream_id=%s "
                "AND lease_token=%s AND lease_until > clock_timestamp() RETURNING event_id",
                (self.tenant_id, self.stream_id, lease.token),
            ).fetchall()
            conn.commit()
        return len(deleted) == len(lease.events)

    def release(self, lease: DeliveryLease) -> None:
        with self.connection() as conn:
            conn.execute(
                "UPDATE gateway_audit_outbox SET lease_token=NULL,lease_until=NULL WHERE tenant_id=%s AND stream_id=%s AND lease_token=%s",
                (self.tenant_id, self.stream_id, lease.token),
            )
            conn.commit()

    def pending(self, event_id: str) -> bool:
        with self.connection() as conn:
            return (
                conn.execute(
                    "SELECT 1 FROM gateway_audit_outbox WHERE tenant_id=%s AND stream_id=%s AND event_id=%s",
                    (self.tenant_id, self.stream_id, event_id),
                ).fetchone()
                is not None
            )

    def backlog_bytes(self) -> int:
        with self.connection() as conn:
            return int(
                conn.execute(
                    "SELECT COALESCE(SUM(payload_bytes),0) FROM gateway_audit_outbox WHERE tenant_id=%s AND stream_id=%s",
                    (self.tenant_id, self.stream_id),
                ).fetchone()[0]
            )
