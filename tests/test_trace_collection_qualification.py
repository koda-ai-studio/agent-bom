"""Qualification receipts must not turn failure or missing work into green evidence."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.run_trace_collection_qualification import assess

pytestmark = pytest.mark.usefixtures("enable_experimental_traces")


def test_qualification_reconciles_native_scoped_records(tmp_path):
    # The harness intentionally configures process-global stores and auth.
    root = Path(__file__).resolve().parents[1]
    output = tmp_path / "qualification"
    subprocess.run(
        [
            sys.executable,
            "-c",
            """
from pathlib import Path
import asyncio
import sys
import anyio.to_thread
import anyio.from_thread
from unittest.mock import patch
from scripts.run_trace_collection_qualification import run
from agent_bom import config
from agent_bom.api.trace_collection import service
config.WORKER_THREAD_LIMIT = 2
loops, limits = set(), set()
original_status = service.status
async def observe_loop():
    loops.add(id(asyncio.get_running_loop()))
    limits.add(anyio.to_thread.current_default_thread_limiter().total_tokens)
def status(*args, **kwargs):
    anyio.from_thread.run(observe_loop)
    return original_status(*args, **kwargs)
with patch.object(service, 'status', status), patch('agent_bom.trace_connectors._validate_pull_url'):
    run(Path(sys.argv[1]), backend='sqlite', workers=1, pages=2, rows=2, p95_limit_ms=5000, slowdown_limit=100)
assert len(loops) == 1, loops
assert limits == {2}, limits
""",
            str(output),
        ],
        cwd=root,
        env={**os.environ, "PYTHONPATH": os.pathsep.join((str(root / "src"), str(root)))},
        check=True,
        capture_output=True,
        timeout=60,
    )
    receipt = json.loads((output / "receipt.json").read_text())
    assert receipt["failed_requests"] == 0
    assert receipt["reconciled"] is True
    assert receipt["expected_observations"] == 8


def attempt(phase, ms, *, ok=True, operation="status"):
    return {"phase": phase, "ms": ms, "ok": ok, "operation": operation}


@pytest.mark.parametrize(
    "rows,reconciled",
    [
        ([], True),
        ([attempt("baseline", 10)], True),
        ([attempt("baseline", 10), attempt("mixed", 10)], False),
        ([attempt("baseline", 10), attempt("mixed", 10), attempt("mixed", 10, ok=False, operation="collect")], True),
        ([attempt("baseline", 10), attempt("mixed", 41)], True),
        ([attempt("baseline", 2000), attempt("mixed", 5001)], True),
    ],
)
def test_missing_failed_unreconciled_or_slow_attempts_fail(rows, reconciled):
    assert not assess(rows, reconciled, p95_limit_ms=5000, slowdown_limit=4)["passed"]


def test_warmup_is_retained_but_excluded_from_baseline():
    rows = [attempt("warmup", 5000), attempt("baseline", 10), attempt("mixed", 30)]
    receipt = assess(rows, True, p95_limit_ms=5000, slowdown_limit=4)
    assert receipt["passed"]
    assert receipt["all_attempts_ms"]["samples"] == 3
    assert receipt["baseline_light_ms"]["p95"] == 10
    assert receipt["light_p95_slowdown"] == 3


def test_runtime_qualification_applies_deployment_worker_budget(monkeypatch):
    import asyncio

    import anyio.to_thread
    import uvicorn

    from agent_bom import config
    from scripts.run_runtime_capacity_qualification import _QualificationServer

    monkeypatch.setattr(config, "WORKER_THREAD_LIMIT", 2)
    observed = []

    async def serve(self, sockets=None):
        observed.append(anyio.to_thread.current_default_thread_limiter().total_tokens)

    monkeypatch.setattr(uvicorn.Server, "serve", serve)

    async def verify():
        limiter = anyio.to_thread.current_default_thread_limiter()
        before = limiter.total_tokens
        try:
            limiter.total_tokens = 31
            await _QualificationServer(uvicorn.Config("unused:app")).serve()
            assert observed == [2], "bypassing provisioning must not bypass deployment backpressure"
        finally:
            limiter.total_tokens = before

    asyncio.run(verify())
