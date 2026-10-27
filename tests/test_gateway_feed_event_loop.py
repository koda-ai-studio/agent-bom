"""The gateway feed must not stall the event loop while it reads its audit log.

`/v1/gateway/feed` and its KPI sibling answer from a JSONL audit log when the
in-process ring buffer is empty. That read is synchronous — open, iterate up to
_MAX_LOG_LINES, json.loads each line, redact each record — and it was called
directly from `async def` handlers. On a large log the whole process stops:
every other tenant's request, every health check, every background task.

AGENT_BOM_LOG is a shipped deployment surface (deploy/docker-compose.runtime-example.yml),
so this is reachable in a normal install, not a synthetic condition.
"""

from __future__ import annotations

import asyncio
import json
import threading

import pytest


def _write_log(path, lines: int) -> None:
    with open(path, "w") as handle:
        for i in range(lines):
            handle.write(
                json.dumps(
                    {
                        "type": "runtime_alert",
                        "tenant_id": "default",
                        "timestamp": "2026-07-29T00:00:00Z",
                        "agent": f"agent-{i % 7}",
                        "action": "blocked",
                        "detail": "x" * 120,
                    }
                )
                + "\n"
            )


def test_jsonl_fallback_reads_the_newest_bounded_records(tmp_path) -> None:
    from agent_bom.api.routes.proxy import _MAX_FEED_LOG_LINES, _read_alerts_from_log

    log = tmp_path / "runtime.jsonl"
    with open(log, "w") as handle:
        for index in range(1_250):
            handle.write(
                json.dumps(
                    {
                        "type": "runtime_alert",
                        "tenant_id": "default",
                        "event_id": f"evt-{index}",
                    }
                )
                + "\n"
            )

    # The bound is now per caller; this asserts the feed's cap specifically.
    alerts = _read_alerts_from_log(log, limit=_MAX_FEED_LOG_LINES)

    assert len(alerts) == 1_000
    assert alerts[0]["event_id"] == "evt-250"
    assert alerts[-1]["event_id"] == "evt-1249"


def _exercise_log_read(tmp_path, monkeypatch, route):
    from agent_bom.api.routes import gateway_feed as feed_mod
    from agent_bom.api.routes import proxy as proxy_mod

    log = tmp_path / "runtime.jsonl"
    _write_log(log, 40_000)
    monkeypatch.setenv("AGENT_BOM_LOG", str(log))
    monkeypatch.setattr(proxy_mod, "_proxy_alerts", type(proxy_mod._proxy_alerts)(maxlen=1000))
    read_alerts = proxy_mod._read_alerts_from_log
    reads = []

    class _Req:
        state = type("S", (), {"tenant_id": "default"})()
        headers: dict[str, str] = {}

    async def _drive():
        loop = asyncio.get_running_loop()
        loop_thread = threading.get_ident()

        def checked_read(*args, **kwargs):
            assert threading.get_ident() != loop_thread, "audit log read ran on the event loop"
            acknowledged = threading.Event()
            loop.call_soon_threadsafe(acknowledged.set)
            # The loop must service a callback while its reader is still busy.
            # This timeout is a deadlock guard, not a shared-runner speed target.
            assert acknowledged.wait(10), "event loop did not respond while the audit log reader was active"
            alerts = read_alerts(*args, **kwargs)
            reads.append(len(alerts))
            return alerts

        monkeypatch.setattr(proxy_mod, "_read_alerts_from_log", checked_read)
        handler = feed_mod.gateway_feed if route == "feed" else feed_mod.gateway_feed_kpis
        return await (handler(_Req(), limit=100) if route == "feed" else handler(_Req()))

    result = asyncio.run(_drive())
    assert reads and all(0 < count <= 40_000 for count in reads)
    assert isinstance(result, dict)
    return result


@pytest.mark.parametrize("route", ["feed", "kpis"])
def test_feed_routes_do_not_block_the_event_loop(tmp_path, monkeypatch, route):
    # Scheduling latency and GIL contention can dominate a short route on CI.
    # Thread identity plus a loop/reader handshake tests the offload contract
    # directly, while still exercising the real 40,000-line JSONL fallback.
    _exercise_log_read(tmp_path, monkeypatch, route)


@pytest.mark.parametrize("route", ["feed", "kpis"])
def test_log_read_guard_rejects_inline_execution(tmp_path, monkeypatch, route):
    import anyio.to_thread

    async def inline(func, *args, **kwargs):
        return func(*args)

    monkeypatch.setattr(anyio.to_thread, "run_sync", inline)
    with pytest.raises(AssertionError, match="audit log read ran on the event loop"):
        _exercise_log_read(tmp_path, monkeypatch, route)


@pytest.mark.parametrize("route", ["feed", "kpis"])
def test_feed_projection_runs_off_the_event_loop(monkeypatch, route):
    from agent_bom.api.routes import gateway_feed as feed_mod

    class _Req:
        state = type("S", (), {"tenant_id": "default"})()
        headers: dict[str, str] = {}

    builder_name = "build_gateway_feed" if route == "feed" else "build_gateway_feed_kpis"
    builder = getattr(feed_mod, builder_name)
    loop_thread = threading.get_ident()
    projected = []

    def checked_projection(**kwargs):
        # Normalization, redaction and sorting must not monopolize the loop
        # after the storage read has yielded back from its worker.
        assert threading.get_ident() != loop_thread, "feed projection ran on the event loop"
        projected.append(True)
        return builder(**kwargs)

    monkeypatch.setattr(feed_mod, builder_name, checked_projection)
    handler = feed_mod.gateway_feed if route == "feed" else feed_mod.gateway_feed_kpis
    result = asyncio.run(handler(_Req(), limit=100) if route == "feed" else handler(_Req()))
    assert projected == [True]
    assert isinstance(result, dict)
