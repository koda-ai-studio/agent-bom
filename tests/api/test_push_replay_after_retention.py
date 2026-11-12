"""A push replayed after retention removed its job is stored again, not refused."""

# ruff: noqa: F811
from __future__ import annotations

import time
from typing import Any

import pytest

from agent_bom.api import stores
from tests.api.test_finding_lifecycle_sequences import (  # noqa: F401
    VULN,
    T,
    _finding,
    _scope_for,
    client,
    push_estate,
    store_kind,
)


def _body(at: str) -> dict[str, Any]:
    return {
        "source_id": "host-asset-a",
        "target_scope": _scope_for("asset-a"),
        "generated_at": at,
        "findings": [_finding("asset-a", *VULN)],
        "packages": [{"name": VULN[1], "version": VULN[2]}],
        "agents": [],
        "summary": {"total_vulnerabilities": 1},
        "scan_run": {"outcome": "complete"},
    }


def _stored(estate, response) -> dict[str, Any]:
    receipt = response.json()
    deadline = time.monotonic() + 60
    while receipt.get("status") not in {"stored", "failed"}:
        assert time.monotonic() < deadline, receipt
        time.sleep(0.05)
        receipt = estate.client.get(receipt["status_url"], headers=estate.headers).json()
    return receipt


def _ingest_workers_idle() -> None:
    """Retention runs hours after a push; wait until its ingest worker has let go of the job id."""
    from agent_bom.api import scan_queue

    deadline = time.monotonic() + 60
    while scan_queue._local_dispatches:
        assert time.monotonic() < deadline, scan_queue._local_dispatches
        time.sleep(0.05)


@pytest.mark.parametrize("prefer", [None, "respond-async"])
def test_identical_push_after_retention_is_stored_again(push_estate, prefer):
    headers = {**push_estate.headers, **({"Prefer": prefer} if prefer else {"Idempotency-Key": "nightly-run-1"})}
    first = push_estate.client.post("/v1/results/push", json=_body(T[1]), headers=headers)
    assert first.status_code in {201, 202}, first.text
    stored = _stored(push_estate, first)
    assert stored["status"] == "stored"
    _ingest_workers_idle()
    assert stores._get_store().cleanup_expired(-86400) >= 1

    again = push_estate.client.post("/v1/results/push", json=_body(T[1]), headers=headers)
    assert again.status_code in {201, 202}, again.text
    restored = _stored(push_estate, again)
    assert restored["status"] == "stored", restored
    assert restored["job_id"] == stored["job_id"]
    assert push_estate.one(VULN[0], "open")["package_version"] == VULN[2]


def test_replay_of_a_retained_push_still_returns_its_receipt(push_estate):
    headers = {**push_estate.headers, "Idempotency-Key": "nightly-run-2"}
    first = push_estate.client.post("/v1/results/push", json=_body(T[1]), headers=headers)
    stored = _stored(push_estate, first)
    replay = push_estate.client.post("/v1/results/push", json=_body(T[1]), headers=headers)
    assert replay.status_code in {200, 201}, replay.text
    assert replay.json()["job_id"] == stored["job_id"]


def test_a_different_body_under_a_retained_key_is_still_a_conflict(push_estate):
    headers = {**push_estate.headers, "Idempotency-Key": "nightly-run-3"}
    _stored(push_estate, push_estate.client.post("/v1/results/push", json=_body(T[1]), headers=headers))
    assert stores._get_store().cleanup_expired(-86400) >= 1
    changed = push_estate.client.post("/v1/results/push", json=_body(T[2]), headers=headers)
    assert changed.status_code in {409, 422}, changed.text
