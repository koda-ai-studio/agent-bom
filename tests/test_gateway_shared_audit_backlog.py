"""Admission drains a shared outbox backlog within the acknowledgement deadline.

``PostgresGatewayOutbox`` is replaced by an in-memory double with the same
contract (ordered claims of at most 100 rows, leases, fenced acknowledgement),
so the admission path is exercised without a database.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest

from agent_bom.api.storage.gateway_delivery import DeliveryLease
from agent_bom.runtime import gateway_shared_audit
from agent_bom.runtime.gateway_contracts import GatewayAuditDeliveryUnavailableError
from agent_bom.runtime.gateway_shared_audit import SharedGatewayAuditSink
from tests.test_gateway_audit_delivery import _event


class FakeOutbox:
    """Ordered, leased queue with the ``PostgresGatewayOutbox`` method contract."""

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self.leases: dict[str, list[str]] = {}
        self.claims = 0

    def enqueue(self, event: dict[str, Any]) -> str:
        self.rows.append({"event_id": event["event_id"], "payload": event, "lease": None})
        return event["event_id"]

    def claim(self, limit: int = 100) -> DeliveryLease | None:
        self.claims += 1
        free = [row for row in self.rows if row["lease"] is None][:limit]
        if not free:
            return None
        token = uuid.uuid4().hex
        for row in free:
            row["lease"] = token
        self.leases[token] = [row["event_id"] for row in free]
        return DeliveryLease(token, [row["payload"] for row in free])

    def acknowledge(self, lease: DeliveryLease) -> bool:
        owned = [row for row in self.rows if row["lease"] == lease.token]
        self.rows = [row for row in self.rows if row["lease"] != lease.token]
        return len(owned) == len(lease.events)

    def release(self, lease: DeliveryLease) -> None:
        for row in self.rows:
            if row["lease"] == lease.token:
                row["lease"] = None

    def pending(self, event_id: str) -> bool:
        return any(row["event_id"] == event_id for row in self.rows)

    def backlog_bytes(self) -> int:
        return sum(len(str(row["payload"])) for row in self.rows)


def _ack(events: list[dict[str, Any]]) -> dict[str, Any]:
    count = len(events)
    return {"accepted_alert_count": count, "durable_accepted_count": count, "durable_conflict_count": 0}


def _sink(store: FakeOutbox, sender) -> SharedGatewayAuditSink:
    return SharedGatewayAuditSink(
        "https://control.example", "placeholder", tenant_id="tenant-a", source_id="gw-1", sender=sender, store=store
    )


def test_admission_drains_backlog_larger_than_one_claim(monkeypatch):
    """250 queued rows ahead of the admission event must not turn a healthy control plane into a 503."""
    store = FakeOutbox()
    for i in range(250):
        store.enqueue(_event(f"backlog-{i}"))
    batches: list[int] = []

    async def sender(payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        batches.append(len(payload["alerts"]))
        return _ack(payload["alerts"])

    # Tighter than the production deadline so a regression fails fast, and far
    # shorter than the retry worker's first backoff.
    monkeypatch.setattr(gateway_shared_audit, "ADMISSION_ACK_TIMEOUT_SECONDS", 2)
    sink = _sink(store, sender)

    asyncio.run(sink.admit_before_tool_execution(_event("admission")))

    assert batches == [100, 100, 51]
    assert store.rows == []
    assert sink.controller.consecutive_failures == 0


def test_admission_fails_closed_when_delivery_keeps_failing(monkeypatch):
    store = FakeOutbox()
    store.enqueue(_event("older"))

    async def sender(payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        raise RuntimeError("control plane down")

    monkeypatch.setattr(gateway_shared_audit, "ADMISSION_ACK_TIMEOUT_SECONDS", 2)
    sink = _sink(store, sender)
    with pytest.raises(GatewayAuditDeliveryUnavailableError):
        asyncio.run(sink.admit_before_tool_execution(_event("admission")))
    # Nothing was delivered and every row is retained for the retry worker.
    assert {row["event_id"] for row in store.rows} == {"older", "admission"}
    assert all(row["lease"] is None for row in store.rows)


def test_admission_waits_for_a_peer_lease_then_reclaims_on_expiry(monkeypatch):
    """A peer that claimed our row and died must not stall admission until the worker's backoff."""
    store = FakeOutbox()
    sent: list[str] = []

    async def sender(payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        sent.extend(event["event_id"] for event in payload["alerts"])
        return _ack(payload["alerts"])

    monkeypatch.setattr(gateway_shared_audit, "ADMISSION_ACK_TIMEOUT_SECONDS", 2)
    sink = _sink(store, sender)
    original_enqueue = store.enqueue

    def enqueue_and_let_peer_claim(event: dict[str, Any]) -> str:
        event_id = original_enqueue(event)
        peer_lease = store.claim()  # the peer wins the row before we flush
        assert peer_lease is not None
        # The peer dies; its lease expires (the fake releases it on the next poll).
        store.expired = peer_lease  # type: ignore[attr-defined]
        return event_id

    original_pending = store.pending

    def pending_then_expire(event_id: str) -> bool:
        lease = getattr(store, "expired", None)
        if lease is not None:
            store.release(lease)
            store.expired = None  # type: ignore[attr-defined]
        return original_pending(event_id)

    monkeypatch.setattr(store, "enqueue", enqueue_and_let_peer_claim)
    monkeypatch.setattr(store, "pending", pending_then_expire)

    asyncio.run(sink.admit_before_tool_execution(_event("admission")))
    assert sent == ["admission"] and store.rows == []
