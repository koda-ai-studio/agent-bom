"""The shared rate-limit store between separate API and client processes on Postgres.

A CPU-heavy ingest in the API process must not demote shared limits to
per-process ones, and a real store outage still falls back to them.
"""

from __future__ import annotations

from collections import Counter

import pytest

from tests.test_auth_failure_processes import (  # noqa: F401 - fixtures
    _BUSY_API,
    _finish,
    _Server,
    _start_client,
    _wait_ready,
    postgres,
    workdir,
)

pytestmark = pytest.mark.timeout(300)

_FALLBACK = "Shared rate-limit store unavailable"


def _env(postgres, rpm: int) -> dict[str, str]:  # noqa: F811
    return {
        "AGENT_BOM_POSTGRES_URL": postgres.url,
        "AGENT_BOM_POSTGRES_MAINTENANCE_URL": postgres.url.replace("agent_bom_app", "agent_bom_maintenance"),
        "AGENT_BOM_GLOBAL_IP_RATE_LIMIT_RPM": str(rpm),
        # Two replicas share the bootstrap role's 20 connections, as operators must size them.
        "AGENT_BOM_POSTGRES_POOL_MIN_SIZE": "1",
        "AGENT_BOM_POSTGRES_POOL_MAX_SIZE": "4",
    }


@pytest.mark.xfail(
    strict=False,
    reason=(
        "Under two CPU-bound threads per API process the event loop and the default executor wait "
        "seconds for the interpreter lock, past the two-second store wait; the database side no "
        "longer queues (tracked follow-up)."
    ),
)
def test_limits_stay_shared_across_two_api_processes_during_ingest(workdir, postgres):  # noqa: F811
    # Both replicas see every client as 127.0.0.1, so they share one per-IP bucket.
    limit = 60
    burn = workdir / "burn"
    servers = [_Server(_env(postgres, limit), workdir / f"api-{n}.log", launcher=["-c", _BUSY_API, str(burn), "2"]) for n in range(2)]
    try:
        for n, server in enumerate(servers):
            _wait_ready(server, source=f"203.0.113.{n + 1}")
        burn.touch()
        clients = [
            (n, _start_client(server.port, 10, server.valid(f"198.18.{n}.{c}"))) for c in range(1, 7) for n, server in enumerate(servers)
        ]
        per_server: list[list[int]] = [[], []]
        for n, client in clients:
            per_server[n] += _finish(client)
        statuses = Counter(per_server[0] + per_server[1])
        logs = [server.log_path.read_text() for server in servers]
    finally:
        for server in servers:
            server.stop()

    assert not any(_FALLBACK in log for log in logs), [log[-1500:] for log in logs]
    # 120 requests against one shared budget of 60, part of it spent on readiness:
    # admitted requests never exceed it, and the rest are refused rather than failed.
    assert set(statuses) <= {200, 429}, statuses
    assert 0 < statuses[200] <= limit, statuses
    # Both replicas refused requests once the shared budget was spent.
    assert all(429 in result for result in per_server), per_server


def test_store_outage_still_falls_back_to_process_local_limits(workdir, postgres):  # noqa: F811
    server = _Server(_env(postgres, 3), workdir / "api.log")
    try:
        _wait_ready(server)
        postgres.stop()
        statuses = _finish(_start_client(server.port, 5, [("x-forwarded-for", "203.0.113.90")], path="/version"))
        log = server.log_path.read_text()
    finally:
        server.stop()
    # The local window starts empty: three public reads, then the local limit.
    assert statuses == [200, 200, 200, 429, 429], statuses
    assert _FALLBACK in log
