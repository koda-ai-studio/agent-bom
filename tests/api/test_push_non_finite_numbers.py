"""A pushed report with a non-finite number is invalid input: 422 on both push paths, nothing stored."""

from __future__ import annotations

import os

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores
from agent_bom.api.fleet_store import InMemoryFleetStore
from agent_bom.api.idempotency_store import InMemoryIdempotencyStore
from agent_bom.api.push_receive import _validate_push_body
from agent_bom.api.scan_queue import reset_local_dispatches_for_tests
from agent_bom.api.server import app, set_fleet_store, set_job_store
from agent_bom.api.store import SQLiteJobStore
from agent_bom.api.stores import set_idempotency_store

ASYNC = {"Prefer": "respond-async"}
_BODY = '{"source_id":"s","idempotency_key":"%s","agents":[{"name":"a","agent_type":"claude-desktop","mcp_servers":[],"score":%s}]}'
NON_FINITE = ["NaN", "Infinity", "-Infinity", "1e999", "-1" + "0" * 400 + ".5"]


def _store_factories() -> list:
    factories = [pytest.param("sqlite", id="sqlite")]
    factories.append(
        pytest.param(
            "postgres",
            id="postgres",
            marks=pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires private Postgres"),
        )
    )
    return factories


@pytest.fixture(params=_store_factories())
def job_store(request: pytest.FixtureRequest, tmp_path):
    originals = (stores._get_store(), stores._get_fleet_store(), stores._get_idempotency_store())
    pool = None
    if request.param == "sqlite":
        store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    else:
        from agent_bom.api.postgres_common import _new_application_pool
        from agent_bom.api.postgres_job_store import PostgresJobStore

        pool = _new_application_pool(min_size=1, max_size=2)
        store = PostgresJobStore(pool)
    set_job_store(store)
    set_fleet_store(InMemoryFleetStore())
    set_idempotency_store(InMemoryIdempotencyStore())
    reset_local_dispatches_for_tests()
    try:
        yield store
    finally:
        set_job_store(originals[0])
        set_fleet_store(originals[1])
        set_idempotency_store(originals[2])
        reset_local_dispatches_for_tests()
        if pool is not None:
            pool.close()


@pytest.mark.parametrize("headers", [{}, ASYNC], ids=["sync", "async"])
@pytest.mark.parametrize("token", NON_FINITE, ids=["nan", "inf", "neg-inf", "exp-overflow", "long-overflow"])
def test_non_finite_number_is_a_422_on_both_push_paths(job_store, headers: dict, token: str) -> None:
    key = f"nf-{abs(hash((token, tuple(headers))))}"
    client = TestClient(app, raise_server_exceptions=False)
    response = client.post(
        "/v1/results/push",
        content=(_BODY % (key, token)).encode(),
        headers={"Content-Type": "application/json", **headers},
    )

    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert detail[0]["type"] == "finite_number"
    assert detail[0]["loc"] == ["body", "agents", 0, "score"]
    assert all(job.source_id != "s" for job in job_store.list_all(all_tenants=True))


def test_finite_numbers_and_number_shaped_strings_still_validate() -> None:
    raw = (_BODY % ("ok", "1e300")).replace('"name":"a"', '"name":"3e512 1e999 NaN"').encode()
    body = _validate_push_body(raw)
    assert body._parsed_body is not None
    assert body._parsed_body["agents"][0]["score"] == 1e300
    assert body._parsed_body["agents"][0]["name"] == "3e512 1e999 NaN"
