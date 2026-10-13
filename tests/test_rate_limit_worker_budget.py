"""Small in-memory limiter buckets must not wait behind blocking I/O work."""

import asyncio
import time

import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from agent_bom.api.middleware import GlobalRateLimitMiddleware, RateLimitMiddleware


@pytest.mark.asyncio
async def test_small_memory_buckets_preserve_limits_without_executor_hops(monkeypatch):
    async def endpoint(request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/v1/data", endpoint)])
    app.add_middleware(RateLimitMiddleware, read_rpm=2)
    app.add_middleware(GlobalRateLimitMiddleware, rpm=10)
    original = asyncio.to_thread
    calls = []

    async def measured(func, *args, **kwargs):
        calls.append(func)
        return await original(func, *args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", measured)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
        responses = [await client.get("/v1/data") for _ in range(3)]
    assert [r.status_code for r in responses] == [200, 200, 429]
    assert [r.headers["x-ratelimit-remaining"] for r in responses] == ["1", "0", "0"]
    assert not calls, "small memory-only hits unnecessarily queued in the executor"


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", ["cleanup", "large"])
async def test_cleanup_and_large_buckets_are_offloaded_without_double_counting(monkeypatch, reason):
    import threading

    from agent_bom.api.rate_limit_store import InMemoryRateLimitStore, record_rate_limit_hit

    store = InMemoryRateLimitStore()
    now = time.time()
    count = store._INLINE_MAX_HITS if reason == "large" else 1
    store._hits["tenant"] = [now] * count
    if reason == "cleanup":
        store._last_cleanup = now - 60
    original = store.hit
    loop_thread = threading.get_ident()
    calls = []

    def hit(*args):
        assert threading.get_ident() != loop_thread
        calls.append(args)
        return original(*args)

    monkeypatch.setattr(store, "hit", hit)
    assert await record_rate_limit_hit(store, "tenant", now) == (count + 1, int(now + 60))
    assert len(calls) == 1


def test_contended_lock_does_not_block_or_consume_inline():
    import threading

    from agent_bom.api.rate_limit_store import InMemoryRateLimitStore

    store = InMemoryRateLimitStore()
    acquired, release = threading.Event(), threading.Event()

    def hold():
        with store._lock:
            acquired.set()
            release.wait(2)

    thread = threading.Thread(target=hold)
    thread.start()
    try:
        assert acquired.wait(2)
        assert store._try_hit_bounded("tenant", time.time()) is None
        assert "tenant" not in store._hits
    finally:
        release.set()
        thread.join(2)


@pytest.mark.asyncio
async def test_other_store_implementations_remain_offloaded():
    import threading

    from agent_bom.api.rate_limit_store import InMemoryRateLimitStore, record_rate_limit_hit

    loop_thread = threading.get_ident()

    class CustomStore(InMemoryRateLimitStore):
        def hit(self, key, now):
            assert threading.get_ident() != loop_thread
            return 4, 123

    assert await record_rate_limit_hit(CustomStore(), "tenant", time.time()) == (4, 123)


@pytest.mark.asyncio
async def test_fast_and_fallback_hits_match_sliding_window_boundaries():
    from agent_bom.api.rate_limit_store import InMemoryRateLimitStore, record_rate_limit_hit

    baseline, candidate = InMemoryRateLimitStore(), InMemoryRateLimitStore()
    now = time.time()
    for offset in [0.0] * 260 + [59.99, 60.0, 60.01, 61.0, 121.0]:
        assert await record_rate_limit_hit(candidate, "tenant", now + offset) == baseline.hit("tenant", now + offset)
    assert candidate._hits == baseline._hits


@pytest.mark.asyncio
async def test_mixed_worker_and_inline_hits_share_atomic_counts():
    from agent_bom.api.rate_limit_store import InMemoryRateLimitStore, record_rate_limit_hit

    store = InMemoryRateLimitStore()
    now = time.time()

    def worker():
        return [store.hit("tenant", now)[0] for _ in range(200)]

    async def inline():
        return [(await record_rate_limit_hit(store, "tenant", now))[0] for _ in range(200)]

    results = await asyncio.gather(asyncio.to_thread(worker), inline())
    assert sorted(results[0] + results[1]) == list(range(1, 401))
    assert store.count("tenant", now) == 400


@pytest.mark.asyncio
async def test_new_bucket_in_large_table_is_offloaded(monkeypatch):
    import threading

    from agent_bom.api.rate_limit_store import InMemoryRateLimitStore, record_rate_limit_hit

    store = InMemoryRateLimitStore()
    now = time.time()
    store._hits = {f"bucket-{i}": [now] for i in range(store._MAX_ENTRIES)}
    original = store.hit
    calls = []
    loop_thread = threading.get_ident()

    def hit(*args):
        assert threading.get_ident() != loop_thread
        calls.append(args)
        return original(*args)

    monkeypatch.setattr(store, "hit", hit)
    assert await record_rate_limit_hit(store, "new-bucket", now) == (1, int(now + 60))
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_postgres_hit_is_always_offloaded(monkeypatch):
    import threading

    from agent_bom.api.rate_limit_store import PostgresRateLimitStore, record_rate_limit_hit

    store = object.__new__(PostgresRateLimitStore)
    loop_thread = threading.get_ident()

    def hit(key, now):
        assert threading.get_ident() != loop_thread
        return 3, 456

    monkeypatch.setattr(store, "hit", hit)
    assert await record_rate_limit_hit(store, "tenant", time.time()) == (3, 456)
