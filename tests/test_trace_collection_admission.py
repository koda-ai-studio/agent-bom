"""Slow collection must leave shared workers available to status reads."""

import asyncio
import threading

import anyio.to_thread
import httpx
import pytest
from fastapi import FastAPI

from agent_bom.api.trace_collection import routes
from agent_bom.api.trace_collection.contracts import CollectionReceipt


@pytest.mark.asyncio
async def test_collection_leaves_worker_available_for_status(monkeypatch):
    from agent_bom import config

    monkeypatch.setattr(config, "WORKER_THREAD_LIMIT", 2)
    limiter = anyio.to_thread.current_default_thread_limiter()
    before = limiter.total_tokens
    limiter.total_tokens = 2
    release = threading.Event()
    entered = threading.Event()
    calls = []

    def collect(tenant, connection, *, actor):
        calls.append(connection)
        entered.set()
        assert release.wait(10)
        return CollectionReceipt(connection_id=connection, status="caught_up")

    monkeypatch.setattr(routes, "require_request_tenant_id", lambda request: "tenant")
    monkeypatch.setattr(routes.service, "collect", collect)
    monkeypatch.setattr(
        routes.service, "status", lambda tenant, connection, **kw: CollectionReceipt(connection_id=connection, status="not_started")
    )
    app = FastAPI()
    app.include_router(routes.router)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
        jobs = [
            asyncio.create_task(client.post("/traces/connectors/langfuse/collect", json={"connection_id": f"connection-{i}"}))
            for i in range(3)
        ]
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            response = await asyncio.wait_for(client.get("/traces/connectors/langfuse/collection?connection_id=light"), 1)
            assert response.status_code == 200
            assert response.json()["connection_id"] == "light"
            assert len(calls) == 1
        finally:
            release.set()
            responses = await asyncio.gather(*jobs)
            limiter.total_tokens = before
    assert [response.status_code for response in responses] == [200] * 3
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_collection_queue_is_bounded_and_cancelled_waiters_do_not_run(monkeypatch):
    from agent_bom import config
    from agent_bom.api.trace_collection import admission

    monkeypatch.setattr(config, "WORKER_THREAD_LIMIT", 2)
    monkeypatch.setattr(admission, "MAX_WAITERS", 1)
    entered, release = threading.Event(), threading.Event()
    calls = []

    def blocked():
        entered.set()
        assert release.wait(10)
        return "finished"

    first = asyncio.create_task(admission.run_collection(blocked))
    queued = None
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        queued = asyncio.create_task(admission.run_collection(lambda: calls.append("cancelled")))
        await asyncio.sleep(0)
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as error:
            await admission.run_collection(lambda: calls.append("overloaded"))
        assert error.value.status_code == 429
        assert error.value.headers == {"Retry-After": "1"}
        queued.cancel()
        with pytest.raises(asyncio.CancelledError):
            await queued
        assert admission._gate().waiting == 0
        assert calls == []
    finally:
        release.set()
        await first
        if queued is not None and not queued.done():
            await queued
    assert await admission.run_collection(lambda: "next") == "next"


@pytest.mark.asyncio
async def test_disconnected_collection_keeps_slot_until_worker_finishes(monkeypatch):
    from agent_bom import config
    from agent_bom.api.trace_collection import admission

    monkeypatch.setattr(config, "WORKER_THREAD_LIMIT", 2)
    entered, release = threading.Event(), threading.Event()
    calls = []

    def blocked():
        entered.set()
        assert release.wait(10)
        raise RuntimeError("fixture storage failure")

    first = asyncio.create_task(admission.run_collection(blocked))
    second = None
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        second = asyncio.create_task(admission.run_collection(lambda: calls.append("next")))
        await asyncio.sleep(0)
        assert admission._gate().waiting == 1
        assert calls == []
    finally:
        release.set()
        if second is not None:
            await asyncio.wait_for(second, 2)
    assert calls == ["next"]
    assert await admission.run_collection(lambda: "recovered") == "recovered"


@pytest.mark.asyncio
async def test_queued_collection_preserves_each_request_tenant_context(monkeypatch):
    from agent_bom import config
    from agent_bom.api.postgres_common import _current_tenant, reset_current_tenant, set_current_tenant
    from agent_bom.api.trace_collection.admission import run_collection

    monkeypatch.setattr(config, "WORKER_THREAD_LIMIT", 2)
    parent_tenant = _current_tenant.get()

    async def request(tenant):
        token = set_current_tenant(tenant)
        try:
            return await run_collection(_current_tenant.get)
        finally:
            reset_current_tenant(token)

    tenants = [f"tenant-{i}" for i in range(8)]
    assert await asyncio.gather(*(request(tenant) for tenant in tenants)) == tenants
    assert _current_tenant.get() == parent_tenant


@pytest.mark.asyncio
async def test_status_uses_one_worker_call_and_keeps_storage_off_loop(monkeypatch):
    from functools import partial

    loop_thread = threading.get_ident()
    calls = []
    original = anyio.to_thread.run_sync

    async def measured(func, *args, **kwargs):
        target = func.func if isinstance(func, partial) else func
        calls.append(target.__name__)
        return await original(func, *args, **kwargs)

    def status(tenant, connection, **kwargs):
        assert threading.get_ident() != loop_thread
        return CollectionReceipt(connection_id=connection, status="not_started")

    monkeypatch.setattr(anyio.to_thread, "run_sync", measured)
    monkeypatch.setattr(routes, "require_request_tenant_id", lambda request: "tenant")
    monkeypatch.setattr(routes.service, "status", status)
    app = FastAPI()
    app.include_router(routes.router)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/traces/connectors/langfuse/collection?connection_id=light")
    assert response.status_code == 200
    assert response.json()["connection_id"] == "light"
    assert len(calls) == 1, calls


@pytest.mark.asyncio
async def test_concurrent_status_calls_preserve_each_tenant_context(monkeypatch):
    from agent_bom.api.postgres_common import _current_tenant, reset_current_tenant, set_current_tenant

    def status(tenant, connection, **kwargs):
        assert _current_tenant.get() == connection
        return CollectionReceipt(connection_id=connection, status="not_started")

    monkeypatch.setattr(routes, "require_request_tenant_id", lambda request: _current_tenant.get())
    monkeypatch.setattr(routes.service, "status", status)
    app = FastAPI()
    app.include_router(routes.router)
    parent = _current_tenant.get()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:

        async def request(tenant):
            token = set_current_tenant(tenant)
            try:
                response = await client.get("/traces/connectors/langfuse/collection", params={"connection_id": tenant})
                assert response.status_code == 200
                return response.json()["connection_id"]
            finally:
                reset_current_tenant(token)

        tenants = [f"tenant-{i}" for i in range(8)]
        assert await asyncio.gather(*(request(tenant) for tenant in tenants)) == tenants
    assert _current_tenant.get() == parent
