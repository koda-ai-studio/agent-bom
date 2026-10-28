"""Real-SQL shared leases, failover and exact-event admission contracts."""

import asyncio
import os
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from agent_bom.api.storage.gateway_delivery import PostgresGatewayOutbox
from agent_bom.runtime.gateway_contracts import GatewayAuditDeliveryUnavailableError
from agent_bom.runtime.gateway_shared_audit import SharedGatewayAuditSink
from tests.test_gateway_audit_delivery import _event

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires migrated Postgres")


@pytest.fixture
def queue():
    tenant = "lease-test-" + uuid.uuid4().hex
    store = PostgresGatewayOutbox(tenant, "shared-gateway")
    yield store
    with store.connection() as conn:
        conn.execute("DELETE FROM gateway_audit_outbox WHERE tenant_id=%s", (tenant,))
        conn.commit()


def event(queue, identity="event-one"):
    return _event(identity, tenant_id=queue.tenant_id)


def test_concurrent_pods_claim_disjoint_events_and_recover_expired_owners(queue):
    for i in range(20):
        queue.enqueue(event(queue, str(i)))
    peer = PostgresGatewayOutbox(queue.tenant_id, queue.stream_id)
    with ThreadPoolExecutor(max_workers=2) as workers:
        leases = list(workers.map(lambda store: store.claim(10), [queue, peer]))
    assert all(lease is not None for lease in leases)
    assert len({row["event_id"] for lease in leases for row in lease.events}) == 20
    assert queue.claim() is None
    # Simulate expiry at the database clock, with no timing-sensitive sleeps.
    with queue.connection() as conn:
        conn.execute(
            "UPDATE gateway_audit_outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=%s", (queue.tenant_id,)
        )
        conn.commit()
    recovered = peer.claim()
    assert recovered is not None and len(recovered.events) == 20
    assert not queue.acknowledge(leases[0])
    queue.release(leases[1])
    assert peer.claim() is None, "stale release must not release the new owner's lease"
    assert peer.acknowledge(recovered)
    assert queue.backlog_bytes() == 0


def test_queue_conflict_bounds_and_rls(queue):
    record = event(queue)
    queue.enqueue(record)
    queue.enqueue(record)
    with pytest.raises(ValueError, match="identity conflict"):
        queue.enqueue({**record, "tool": "changed"})
    peer = PostgresGatewayOutbox("foreign-" + uuid.uuid4().hex, queue.stream_id)
    with peer.connection() as conn:
        assert conn.execute("SELECT event_id FROM gateway_audit_outbox WHERE tenant_id=%s", (queue.tenant_id,)).fetchall() == []
    assert peer.claim() is None
    with pytest.raises(ValueError, match="tenant mismatch"):
        peer.enqueue(record)
    queue.max_bytes = queue.backlog_bytes()
    with pytest.raises(ValueError, match="full"):
        queue.enqueue(event(queue, "next"))


def test_killed_delivery_process_leaves_a_recoverable_lease(queue):
    queue.enqueue(event(queue))
    program = (
        "import sys,time; from agent_bom.api.storage.gateway_delivery import PostgresGatewayOutbox; "
        "q=PostgresGatewayOutbox(sys.argv[1],sys.argv[2]); lease=q.claim(); "
        "print(lease.token,flush=True); time.sleep(60)"
    )
    process = subprocess.Popen([sys.executable, "-c", program, queue.tenant_id, queue.stream_id], stdout=subprocess.PIPE, text=True)
    try:
        assert process.stdout is not None
        token = process.stdout.readline().strip()
        assert token
        assert queue.claim() is None
        process.kill()
        process.wait(timeout=10)
        with queue.connection() as conn:
            conn.execute(
                "UPDATE gateway_audit_outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=%s AND lease_token=%s",
                (queue.tenant_id, token),
            )
            conn.commit()
        recovered = queue.claim()
        assert recovered is not None and recovered.token != token
        assert recovered.events[0]["event_id"] == "event-one"
        assert queue.acknowledge(recovered)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)


@pytest.mark.asyncio
async def test_partial_remote_ack_does_not_delete_shared_evidence(queue):
    async def partial(payload, headers):
        return {"accepted_alert_count": 1, "durable_accepted_count": 0}

    sink = SharedGatewayAuditSink(
        "https://api.example", "placeholder", tenant_id=queue.tenant_id, source_id="gateway", store=queue, sender=partial
    )
    with pytest.raises(GatewayAuditDeliveryUnavailableError):
        await sink.admit_before_tool_execution(event(queue))
    assert queue.pending("event-one")
    assert not sink.health()["accepting_events"]


@pytest.mark.asyncio
async def test_sink_requires_exact_event_ack_and_restart_recovers_lost_ack(queue):
    calls = []

    async def unavailable(payload, headers):
        calls.append(payload)
        raise OSError("untrusted failure details")

    sink = SharedGatewayAuditSink(
        "https://api.example", "placeholder", tenant_id=queue.tenant_id, source_id="gateway", store=queue, sender=unavailable
    )
    with pytest.raises(GatewayAuditDeliveryUnavailableError, match="shared audit delivery unavailable"):
        await sink.admit_before_tool_execution(event(queue))
    assert queue.pending("event-one")

    async def acknowledged(payload, headers):
        calls.append(payload)
        size = len(payload["alerts"])
        return {"durable_duplicate_count": size, "duplicate_alert_count": size}

    recovered = SharedGatewayAuditSink(
        "https://api.example", "placeholder", tenant_id=queue.tenant_id, source_id="gateway", store=queue, sender=acknowledged
    )
    assert await recovered.flush_once()
    assert not queue.pending("event-one")
    assert calls[0] == calls[1], "retry preserves the producer event and idempotency identity"
    with pytest.raises(GatewayAuditDeliveryUnavailableError):
        await recovered.bind_authenticated_tenant("foreign", "placeholder")
    await recovered.aclose()
    with pytest.raises(GatewayAuditDeliveryUnavailableError):
        await recovered.admit_before_tool_execution(event(queue, "closed"))


@pytest.mark.asyncio
async def test_cancelled_delivery_remains_recoverable(queue):
    started = asyncio.Event()

    async def delayed(payload, headers):
        started.set()
        await asyncio.Future()

    sink = SharedGatewayAuditSink(
        "https://api.example", "placeholder", tenant_id=queue.tenant_id, source_id="gateway", store=queue, sender=delayed
    )
    queue.enqueue(event(queue))
    task = asyncio.create_task(sink.flush_once())
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert queue.claim() is not None


def test_concurrent_admission_cannot_exceed_shared_budget(queue):
    queue.enqueue(event(queue, "sample"))
    queue.max_bytes = queue.backlog_bytes() * 2
    with queue.connection() as conn:
        conn.execute("DELETE FROM gateway_audit_outbox WHERE tenant_id=%s", (queue.tenant_id,))
        conn.commit()

    def enqueue(identity):
        try:
            queue.enqueue(event(queue, identity))
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(max_workers=4) as workers:
        accepted = list(workers.map(enqueue, ["event1", "event2", "event3", "event4"]))
    assert sum(accepted) == 2
    assert queue.backlog_bytes() <= queue.max_bytes


@pytest.mark.asyncio
async def test_another_workers_lease_cannot_admit_an_unacknowledged_event(queue, monkeypatch):
    monkeypatch.setattr("agent_bom.runtime.gateway_shared_audit.ADMISSION_ACK_TIMEOUT_SECONDS", 0.1, raising=False)
    record = event(queue)
    queue.enqueue(record)
    lease = queue.claim()
    assert lease is not None

    async def unexpected_send(payload, headers):
        pytest.fail("a held lease cannot be sent by another worker")

    sink = SharedGatewayAuditSink(
        "https://api.example", "placeholder", tenant_id=queue.tenant_id, source_id="gateway", store=queue, sender=unexpected_send
    )
    with pytest.raises(GatewayAuditDeliveryUnavailableError):
        await sink.admit_before_tool_execution(record)
    assert queue.pending("event-one")
    assert sink.health()["durable"], "pending remote acknowledgement does not mean the durable database is unavailable"
    assert not sink.health()["accepting_events"]


@pytest.mark.asyncio
async def test_admission_waits_for_peer_to_acknowledge_the_exact_event(queue):
    record = event(queue)
    queue.enqueue(record)
    lease = queue.claim()
    assert lease is not None

    async def unexpected_send(payload, headers):
        pytest.fail("the requester must not steal a peer's live lease")

    sink = SharedGatewayAuditSink(
        "https://api.example", "placeholder", tenant_id=queue.tenant_id, source_id="gateway", store=queue, sender=unexpected_send
    )
    admission = asyncio.create_task(sink.admit_before_tool_execution(record))
    try:
        await asyncio.sleep(0.1)
        assert not admission.done(), "peer delivery in progress must not spuriously reject the call"
        assert await asyncio.to_thread(queue.acknowledge, lease)
        await asyncio.wait_for(admission, timeout=2)
        assert not queue.pending(record["event_id"])
        assert sink.health()["remote_acknowledgement_available"]
    finally:
        admission.cancel()
        await asyncio.gather(admission, return_exceptions=True)
