"""A worker must never retire a current-estate generation another worker process just promoted."""

from __future__ import annotations

import multiprocessing
import threading
from typing import Any

import pytest

from agent_bom.api.current_graph import CurrentGraphStore
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.store import SQLiteJobStore
from tests.api.test_current_graph_estate import record
from tests.api.test_current_graph_read_locking import _pause_before_build

TENANT = "history-tenant"


class _UnrevisionedJobStore(SQLiteJobStore):
    """A shared durable job store without a mutation revision (the full-fingerprint path)."""

    overview_evidence_revision = None


def _job_store(kind: str, path: str) -> Any:
    return (_UnrevisionedJobStore if kind == "unrevisioned" else SQLiteJobStore)(path)


def _resolve_in_another_process(kind: str, jobs_path: str, graph_path: str, state_dir: str, conn: Any) -> None:
    import os

    os.environ["AGENT_BOM_STATE_DIR"] = state_dir
    try:
        store = CurrentGraphStore(SQLiteGraphStore(graph_path), _job_store(kind, jobs_path))
        conn.send(("ok", store._resolve_current_id(TENANT)))
    except BaseException as exc:  # noqa: BLE001 - report every child failure to the parent
        conn.send(("error", repr(exc)))
    finally:
        conn.close()


@pytest.mark.parametrize("kind", ["revisioned", "unrevisioned"])
def test_stale_worker_never_retires_a_generation_another_process_promoted(kind, tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(state_dir))
    jobs_path, graph_path = str(tmp_path / "jobs.db"), str(tmp_path / "graph.db")
    estate = (_job_store(kind, jobs_path), SQLiteGraphStore(graph_path))
    record(estate, 8, "repo-a", "package-a")
    worker = CurrentGraphStore(estate[1], estate[0])
    assert worker._cache_directory is None, "both workers must share the durable projection cache"

    # Cover the child response (60s), exit (30s) and setup before releasing the gate.
    paused, resume = _pause_before_build(worker, "stale-worker", resume_timeout=120)
    stale: list[Any] = []

    def resolve() -> None:
        try:
            stale.append(worker._resolve_current_id(TENANT))
        except Exception as exc:  # noqa: BLE001 - the assertion below reports it
            stale.append(exc)

    resolver = threading.Thread(target=resolve, name="stale-worker")
    resolver.start()
    assert paused.wait(10)
    record(estate, 9, "repo-b", "package-b")

    context = multiprocessing.get_context("spawn")
    parent_end, child_end = context.Pipe(duplex=False)
    other = context.Process(target=_resolve_in_another_process, args=(kind, jobs_path, graph_path, str(state_dir), child_end))
    other.start()
    child_end.close()
    try:
        assert parent_end.poll(60), "the other worker never answered"
        status, promoted = parent_end.recv()
        other.join(30)
        assert status == "ok", promoted
    finally:
        resume.set()
        resolver.join(10)
        parent_end.close()
        if other.is_alive():
            other.terminate()
            other.join(10)
    assert not resolver.is_alive()

    assert worker._projection_store.snapshot_identity(tenant_id=TENANT, scan_id=promoted)[1], "foreign promotion was retired"
    assert stale == [promoted]
    assert set(worker.load_graph(tenant_id=TENANT).nodes) == {"package-a", "package-b"}
