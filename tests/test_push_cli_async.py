"""CLI push against asynchronous ingest: stable keys, honest receipts, no duplicate jobs."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import httpx
import pytest

from agent_bom.push import _push_async, _push_status_url, _push_timeout_seconds, sanitize_results

PUSH_URL = "http://localhost:8422/v1/results/push"


def _report() -> dict:
    return {"agents": [{"name": "proj", "agent_type": "claude-desktop", "mcp_servers": []}], "summary": {"total_packages": 0}}


class _ScriptedServer:
    """A transport answering POSTs and status GETs from scripted responses."""

    def __init__(self, posts: list[httpx.Response], gets: list[httpx.Response] | None = None) -> None:
        self.posts = posts
        self.gets = gets or []
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        queue = self.posts if request.method == "POST" else self.gets
        return queue.pop(0)

    def client(self, **_kwargs: object) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


def _run(server: _ScriptedServer, url: str = PUSH_URL, **kwargs: object) -> tuple[bool, dict | None]:
    with (
        patch("agent_bom.http_client.create_client", side_effect=server.client),
        patch("agent_bom.push.asyncio.sleep", return_value=None),
        patch("agent_bom.security.validate_url"),
    ):
        return asyncio.run(_push_async(url, _report(), return_body=True, base_delay_seconds=0, **kwargs))  # type: ignore[arg-type]


def _accepted(job_id: str = "job-1") -> httpx.Response:
    return httpx.Response(
        202,
        json={"job_id": job_id, "status": "accepted", "ingest": "queued", "status_url": f"/v1/results/push/{job_id}"},
        headers={"Retry-After": "1"},
    )


def test_the_same_report_always_carries_the_same_key_per_destination() -> None:
    first = sanitize_results(_report(), source_id="host-a", idempotency_target=PUSH_URL)
    rerun = sanitize_results(_report(), source_id="host-a", idempotency_target=PUSH_URL)
    elsewhere = sanitize_results(_report(), source_id="host-a", idempotency_target="https://other.example/v1/results/push")
    changed = sanitize_results({**_report(), "summary": {"total_packages": 1}}, source_id="host-a", idempotency_target=PUSH_URL)

    assert first["idempotency_key"] == rerun["idempotency_key"]
    assert first["idempotency_key"] != elsewhere["idempotency_key"]
    assert first["idempotency_key"] != changed["idempotency_key"]
    assert sanitize_results(_report(), idempotency_key="explicit")["idempotency_key"] == "explicit"


def test_accepted_push_is_polled_until_stored() -> None:
    stored = {"job_id": "job-1", "status": "stored", "graph_persistence": {"status": "persisted"}}
    server = _ScriptedServer(
        [_accepted()], [httpx.Response(200, json={"status": "accepted", "ingest": "running"}), httpx.Response(200, json=stored)]
    )

    ok, body = _run(server, url="https://cp.example/prefix/v1/results/push")

    assert ok is True
    assert body == stored
    post, *polls = server.requests
    assert post.headers["Prefer"] == "respond-async"
    assert post.headers["Idempotency-Key"].startswith("report-")
    assert [str(request.url) for request in polls] == ["https://cp.example/prefix/v1/results/push/job-1"] * 2


def test_a_committed_push_is_never_reported_as_failed_when_the_wait_budget_ends(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_PUSH_WAIT_SECONDS", "0")
    server = _ScriptedServer([_accepted()])

    ok, body = _run(server)

    assert ok is True
    assert body is not None and body["status"] == "accepted"


def test_in_flight_409_with_retry_after_is_retried_with_the_same_key() -> None:
    server = _ScriptedServer(
        [
            httpx.Response(409, json={"detail": "still committing"}, headers={"Retry-After": "1"}),
            httpx.Response(201, json={"job_id": "job-1", "status": "stored"}),
        ]
    )

    ok, body = _run(server)

    assert ok is True and body == {"job_id": "job-1", "status": "stored"}
    keys = {request.headers["Idempotency-Key"] for request in server.requests}
    assert len(keys) == 1


def test_a_conflicting_409_without_retry_after_is_not_retried() -> None:
    server = _ScriptedServer([httpx.Response(409, json={"detail": "different body"})])

    ok, body = _run(server)

    assert (ok, body) == (False, None)
    assert len(server.requests) == 1


def test_failed_server_ingest_resubmits_the_same_report() -> None:
    server = _ScriptedServer(
        [_accepted(), _accepted()],
        [httpx.Response(200, json={"status": "failed"}), httpx.Response(200, json={"job_id": "job-1", "status": "stored"})],
    )

    ok, body = _run(server)

    assert ok is True and body is not None and body["status"] == "stored"
    posts = [request for request in server.requests if request.method == "POST"]
    assert len(posts) == 2
    assert posts[0].content == posts[1].content


@pytest.mark.parametrize("status_url", ["https://evil.example/v1/x", "//evil.example/v1/x", "/v1/../admin", 42, None])
def test_status_url_never_leaves_the_push_destination(status_url: object) -> None:
    assert _push_status_url(PUSH_URL, status_url) is None


def test_timeout_scales_with_the_decoded_report_size() -> None:
    assert 30.0 <= _push_timeout_seconds(1024, compressed=False) < 31.0
    assert _push_timeout_seconds(100 * 1024 * 1024, compressed=False) > 200
    assert _push_timeout_seconds(30 * 1024 * 1024, compressed=True) == 900.0


def test_cli_rerun_of_the_same_report_creates_one_server_job(monkeypatch: pytest.MonkeyPatch) -> None:
    """End to end against the real app: two pushes of one report dedupe onto one job."""

    from agent_bom.api import push_ingest_worker, stores
    from agent_bom.api.fleet_store import InMemoryFleetStore
    from agent_bom.api.idempotency_store import InMemoryIdempotencyStore
    from agent_bom.api.scan_queue import reset_local_dispatches_for_tests
    from agent_bom.api.server import app, set_fleet_store, set_job_store
    from agent_bom.api.store import InMemoryJobStore
    from agent_bom.api.stores import set_idempotency_store

    originals = (stores._get_store(), stores._get_fleet_store(), stores._get_idempotency_store())
    set_job_store(InMemoryJobStore())
    set_fleet_store(InMemoryFleetStore())
    set_idempotency_store(InMemoryIdempotencyStore())
    reset_local_dispatches_for_tests()
    persisted: list[str] = []

    def _persist(job, report, **_kwargs) -> None:  # noqa: ANN001
        persisted.append(job.job_id)
        report["graph_persistence"] = {"status": "persisted", "scan_id": job.job_id}

    monkeypatch.setattr(push_ingest_worker, "_persist_push_graph", _persist)
    monkeypatch.setenv("AGENT_BOM_PUSH_SOURCE_ID", "host-rerun")

    def _client(**_kwargs: object) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost:8422")

    async def _push_twice() -> list[tuple[bool, dict | None]]:
        results = []
        for _ in range(2):
            results.append(await _push_async(PUSH_URL, _report(), return_body=True))
        return results

    try:
        with patch("agent_bom.http_client.create_client", side_effect=_client), patch("agent_bom.security.validate_url"):
            first, second = asyncio.run(_push_twice())
        assert first[0] is True and second[0] is True
        assert first[1] is not None and second[1] is not None
        assert first[1]["status"] == second[1]["status"] == "stored"
        assert first[1]["job_id"] == second[1]["job_id"]
        assert len(stores._get_store().list_all(all_tenants=True)) == 1
        assert persisted == [first[1]["job_id"]]
    finally:
        set_job_store(originals[0])
        set_fleet_store(originals[1])
        set_idempotency_store(originals[2])
        reset_local_dispatches_for_tests()
