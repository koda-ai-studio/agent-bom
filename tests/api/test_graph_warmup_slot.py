"""Post-commit warm-ups share one slot: each loads whole graphs, so running them at once multiplied peak memory."""

from __future__ import annotations

import threading
import time

from agent_bom.api import exec_read_prewarm, finding_reachability_prewarm, graph_rollup_prewarm


def test_rollup_reachability_and_exec_warm_ups_never_overlap(monkeypatch):
    lock = threading.Lock()
    running: list[str] = []
    overlaps: list[tuple[str, ...]] = []
    finished = threading.Event()
    done: list[str] = []

    def work(name):
        with lock:
            running.append(name)
            if len(running) > 1:
                overlaps.append(tuple(running))
        time.sleep(0.2)
        with lock:
            running.remove(name)
            done.append(name)
            if len(done) == 3:
                finished.set()

    monkeypatch.setattr(graph_rollup_prewarm, "prewarm_rollup", lambda store, *, tenant_id: work("rollup"))
    monkeypatch.setattr(finding_reachability_prewarm, "prewarm_reachability_index", lambda store, *, tenant_id: work("reachability"))

    async def exec_reads(tenant_id):
        work("exec")
        return {}

    monkeypatch.setattr(exec_read_prewarm, "warm_exec_reads", exec_reads)
    monkeypatch.setattr(exec_read_prewarm, "exec_prewarm_enabled", lambda: True)
    monkeypatch.setenv("AGENT_BOM_GRAPH_ROLLUP_PREWARM", "1")
    monkeypatch.setenv("AGENT_BOM_FINDING_REACHABILITY_PREWARM", "1")

    graph_rollup_prewarm.schedule_rollup_prewarm(lambda: object(), tenant_id="slot-tenant")
    finding_reachability_prewarm.schedule_reachability_prewarm(lambda: object(), tenant_id="slot-tenant")
    exec_read_prewarm.schedule_exec_prewarm("slot-tenant")

    assert finished.wait(10), done
    assert graph_rollup_prewarm.wait_idle(5) and finding_reachability_prewarm.wait_idle(5)
    assert sorted(done) == ["exec", "reachability", "rollup"]
    assert overlaps == []
