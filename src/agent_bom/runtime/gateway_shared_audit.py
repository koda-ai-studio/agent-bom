"""Shared Postgres audit delivery for tenant-bound gateway replica sets."""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any

from agent_bom.api.storage.gateway_delivery import PostgresGatewayOutbox
from agent_bom.runtime.audit_delivery import AuditDeliveryController
from agent_bom.runtime.gateway_audit import ControlPlaneAuditSink, _send_gateway_audit_batch
from agent_bom.runtime.gateway_contracts import GatewayAuditDeliveryUnavailableError, GatewayAuditSender
from agent_bom.runtime.gateway_events import canonicalize_gateway_enforcement_event, ensure_gateway_event_identity

ADMISSION_ACK_TIMEOUT_SECONDS = 20


class SharedGatewayAuditSink(ControlPlaneAuditSink):
    """Cross-pod retries with fenced acknowledgement and fail-closed admission.

    Each replica set serves one authenticated tenant using a dedicated delivery
    credential. Caller tokens and credentials are never stored in the queue.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        tenant_id: str,
        source_id: str,
        sender: GatewayAuditSender | None = None,
        store: PostgresGatewayOutbox | None = None,
    ) -> None:
        self._base_url, self._token = base_url.rstrip("/"), token
        self._tenant_id, self._source_id = tenant_id, source_id
        stream = hashlib.sha256(f"{self._base_url}\0{source_id}\0{tenant_id}".encode()).hexdigest()
        self._session_id = "gateway-" + stream[:20]
        self.store = store or PostgresGatewayOutbox(tenant_id, stream)
        self._sender = sender or self._send
        self._lock = asyncio.Lock()
        self._worker: asyncio.Task[None] | None = None
        self._closed = False
        self._available = False
        self._remote_ack = False
        self._backlog = 0
        self.controller = AuditDeliveryController()

    async def _send(self, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        return await _send_gateway_audit_batch(self._base_url + "/v1/proxy/audit", payload, headers)

    async def bind_authenticated_tenant(self, tenant_id: str, token: str | None) -> None:
        if tenant_id != self._tenant_id:
            raise GatewayAuditDeliveryUnavailableError("shared audit deployment is bound to another tenant")

    async def _record(self, event: dict[str, Any], *, require_ack: bool) -> None:
        if self._closed:
            raise GatewayAuditDeliveryUnavailableError("shared audit delivery is closed")
        try:
            record = canonicalize_gateway_enforcement_event(ensure_gateway_event_identity(event))
            event_id = await asyncio.to_thread(self.store.enqueue, record)
            self._available = True
            if require_ack:
                await self._flush_until_acknowledged(event_id)
            else:
                await self.flush_once()
        except asyncio.CancelledError:
            raise
        except (GatewayAuditDeliveryUnavailableError, TimeoutError):
            self._remote_ack = False
            raise GatewayAuditDeliveryUnavailableError("shared audit delivery unavailable") from None
        except Exception:
            self._available = False
            raise GatewayAuditDeliveryUnavailableError("shared audit delivery unavailable") from None

    async def _flush_until_acknowledged(self, event_id: str) -> None:
        # A peer may claim the event between enqueue and flush. Wait for that
        # exact row's fenced deletion, never another batch's acknowledgement.
        async with asyncio.timeout(ADMISSION_ACK_TIMEOUT_SECONDS):
            await self.flush_once()
            delay = 0.05
            while await asyncio.to_thread(self.store.pending, event_id):
                if not self._available or self.controller.consecutive_failures:
                    raise GatewayAuditDeliveryUnavailableError("durable acknowledgement is pending")
                await asyncio.sleep(delay)
                delay = min(delay * 2, 0.25)
            self._remote_ack = True

    async def __call__(self, event: dict[str, Any]) -> None:
        await self._record(event, require_ack=False)

    async def admit_before_tool_execution(self, event: dict[str, Any]) -> None:
        await self._record(event, require_ack=True)

    async def flush_once(self) -> bool:
        async with self._lock:
            lease = None
            try:
                self._backlog = await asyncio.to_thread(self.store.backlog_bytes)
                self._available = True
                if self.controller.is_circuit_open():
                    return False
                lease = await asyncio.to_thread(self.store.claim)
                if lease is None:
                    return self._backlog == 0
                # Timeout is shorter than the database-clock lease. Expiry still
                # fences acknowledgement if this process was suspended mid-send.
                response = await asyncio.wait_for(self._sender(self._payload(lease.events), self._headers()), timeout=20)
                self._validate_acknowledgement(lease.events, response)
                if not await asyncio.to_thread(self.store.acknowledge, lease):
                    raise GatewayAuditDeliveryUnavailableError("delivery lease no longer owned")
                self._remote_ack = True
                self.controller.record_success()
                self._backlog = await asyncio.to_thread(self.store.backlog_bytes)
                return True
            except asyncio.CancelledError:
                if lease is not None:
                    await asyncio.to_thread(self.store.release, lease)
                raise
            except Exception:
                self._remote_ack = False
                self.controller.record_failure()
                if lease is not None:
                    try:
                        await asyncio.to_thread(self.store.release, lease)
                    except Exception:
                        self._available = False
                else:
                    self._available = False
                return False

    async def _retry_loop(self) -> None:
        while True:
            await asyncio.sleep(self.controller.current_backoff_seconds())
            await self.flush_once()

    async def start(self) -> None:
        if self._worker is None:
            self._closed = False
            await self.flush_once()
            self._worker = asyncio.create_task(self._retry_loop(), name="gateway-shared-audit-delivery")

    async def aclose(self) -> None:
        self._closed = True
        if self._worker is not None:
            self._worker.cancel()
            try:
                await self._worker
            except asyncio.CancelledError:
                pass
            self._worker = None

    def health(self) -> dict[str, str | int | bool]:
        # No blocking database calls on the HTTP event loop. Admission always
        # verifies the store and exact event; the worker refreshes this snapshot.
        accepting = self._available and not self._closed and (self._remote_ack or self._backlog == 0)
        return {
            "configured": True,
            "mode": "shared_postgres",
            "status": "healthy" if accepting else "degraded",
            "durable": self._available,
            "accepting_events": accepting,
            "backlog_observable": self._available,
            "remote_acknowledgement_available": self._remote_ack,
            "backlog_bytes": self._backlog,
            "pending_audit_state": self._backlog > 0 or not self._available,
            "retry_worker_running": self._worker is not None and not self._worker.done(),
            "dropped_events": 0,
            "lease_seconds": self.store.lease_seconds,
        }
