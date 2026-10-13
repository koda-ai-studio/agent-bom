"""Demo-only refresh must not queue ordinary requests behind storage workers."""

import asyncio
import threading

import anyio.to_thread
import httpx
import pytest
from fastapi import Depends, FastAPI

from agent_bom.api.demo_refresh import demo_daily_evidence_dependency


@pytest.mark.asyncio
async def test_disabled_demo_dependency_does_not_wait_for_a_worker(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    app = FastAPI(dependencies=[Depends(demo_daily_evidence_dependency)])

    @app.get("/")
    async def endpoint():
        return {"ready": True}

    limiter = anyio.to_thread.current_default_thread_limiter()
    before = limiter.total_tokens
    limiter.total_tokens = 1
    borrower = object()
    await limiter.acquire_on_behalf_of(borrower)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
            response = await asyncio.wait_for(client.get("/"), 0.5)
            assert response.json() == {"ready": True}
    finally:
        limiter.release_on_behalf_of(borrower)
        limiter.total_tokens = before


@pytest.mark.asyncio
async def test_enabled_demo_refresh_runs_off_loop_and_retains_failure_policy(monkeypatch, caplog):
    from agent_bom.demo_estate import bootstrap

    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "true")
    loop_thread = threading.get_ident()
    calls = []

    def refresh():
        calls.append(threading.get_ident())
        raise RuntimeError("private-demo-refresh-error")

    monkeypatch.setattr(bootstrap, "refresh_demo_daily_evidence", refresh)
    app = FastAPI(dependencies=[Depends(demo_daily_evidence_dependency)])

    @app.get("/")
    async def endpoint():
        return {"ready": True}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
        assert (await client.get("/")).status_code == 200
    assert len(calls) == 1
    assert calls[0] != loop_thread
    assert "refresh skipped" in caplog.text
    assert "private-demo-refresh-error" not in caplog.text
