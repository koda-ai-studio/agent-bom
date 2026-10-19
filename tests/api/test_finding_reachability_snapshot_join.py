"""Finding reachability joins the whole materialized path snapshot, not a top-N window."""

from __future__ import annotations

from agent_bom.api import finding_reachability
from agent_bom.api.finding_reachability import project_persisted_graph_reachability
from agent_bom.graph import AttackPath


class PagedStore:
    """Honors offset/limit like the real stores; counts reads."""

    def __init__(self, paths: list[AttackPath], *, scan_id: str = "current-estate:abc", created_at: str = "2026-10-18T00:00:00Z") -> None:
        self.paths = paths
        self.scan_id = scan_id
        self.created_at = created_at
        self.calls: list[dict[str, object]] = []

    def attack_paths(self, **kwargs):
        self.calls.append(kwargs)
        offset, limit = int(kwargs["offset"]), int(kwargs["limit"])
        return self.scan_id, self.created_at, self.paths[offset : offset + limit], len(self.paths)


def _path(index: int, *, edge: str = "exploitable_via") -> AttackPath:
    return AttackPath(
        source=f"agent:a{index}",
        target=f"vuln:CVE-2026-{index:05d}",
        hops=[f"agent:a{index}", f"pkg:p{index}", f"vuln:CVE-2026-{index:05d}"],
        edges=[edge, "vulnerable_to"],
        finding_ids=[f"occurrence-{index}"],
        vuln_ids=[f"CVE-2026-{index:05d}"],
    )


def setup_function() -> None:
    finding_reachability.clear_reachability_index_cache()


def test_rows_whose_paths_rank_below_the_first_thousand_are_still_reachable():
    store = PagedStore([_path(index) for index in range(2_500)])
    rows = [{"id": "occurrence-1800", "cve_id": "CVE-2026-01800", "scan_id": "showcase"}]

    result = project_persisted_graph_reachability(rows, graph_store=store, tenant_id="t", scan_id=None)  # type: ignore[arg-type]

    assert result.rows[0]["graph_reachable"] is True
    assert result.rows[0]["graph_reachable_from_agents"] == ["agent:a1800"]
    assert result.truncated is False


def test_default_view_does_not_skip_rows_stamped_with_their_job_scan_id():
    """The current-estate snapshot id never equals a job's scan id."""
    store = PagedStore([_path(1)])
    rows = [{"finding_id": "occurrence-1", "cve_id": "CVE-2026-00001", "scan_id": "showcase"}]

    result = project_persisted_graph_reachability(rows, graph_store=store, tenant_id="t", scan_id=None)  # type: ignore[arg-type]

    assert result.rows[0]["graph_reachable"] is True


def test_explicit_scan_request_still_refuses_rows_from_another_scan():
    store = PagedStore([_path(1)], scan_id="scan-a")
    rows = [{"finding_id": "occurrence-1", "cve_id": "CVE-2026-00001", "scan_id": "scan-b"}]

    result = project_persisted_graph_reachability(rows, graph_store=store, tenant_id="t", scan_id="scan-a")  # type: ignore[arg-type]

    assert result.rows[0]["graph_reachable"] is None


def test_snapshot_index_is_built_once_per_snapshot_identity():
    store = PagedStore([_path(index) for index in range(2_500)])
    rows = [{"id": "occurrence-7", "cve_id": "CVE-2026-00007"}]

    for _ in range(3):
        project_persisted_graph_reachability(rows, graph_store=store, tenant_id="t", scan_id=None)  # type: ignore[arg-type]
    full_reads = [call for call in store.calls if int(call["limit"]) > 1]
    assert len(full_reads) == 3  # 2,500 paths in 1,000-path pages, read once

    store.created_at = "2026-10-19T00:00:00Z"  # a new snapshot generation invalidates the index
    project_persisted_graph_reachability(rows, graph_store=store, tenant_id="t", scan_id=None)  # type: ignore[arg-type]
    assert len([call for call in store.calls if int(call["limit"]) > 1]) == 6


def test_short_read_is_not_cached():
    """A snapshot that reports more paths than a read returns is retried next time."""

    class ShortThenFull(PagedStore):
        short = True

        def attack_paths(self, **kwargs):
            sid, created, page, total = super().attack_paths(**kwargs)
            if self.short and int(kwargs["limit"]) > 1:
                self.short = False
                return sid, created, [], total
            return sid, created, page, total

    store = ShortThenFull([_path(1)])
    rows = [{"finding_id": "occurrence-1", "cve_id": "CVE-2026-00001"}]
    first = project_persisted_graph_reachability(rows, graph_store=store, tenant_id="t", scan_id=None)  # type: ignore[arg-type]
    assert first.rows[0]["graph_reachable"] is None and first.truncated is True
    second = project_persisted_graph_reachability(rows, graph_store=store, tenant_id="t", scan_id=None)  # type: ignore[arg-type]
    assert second.rows[0]["graph_reachable"] is True and second.truncated is False


def test_index_is_tenant_scoped():
    store = PagedStore([_path(1)])
    rows = [{"finding_id": "occurrence-1", "cve_id": "CVE-2026-00001"}]
    project_persisted_graph_reachability(rows, graph_store=store, tenant_id="tenant-a", scan_id=None)  # type: ignore[arg-type]

    empty = PagedStore([])
    result = project_persisted_graph_reachability(rows, graph_store=empty, tenant_id="tenant-b", scan_id=None)  # type: ignore[arg-type]
    assert result.rows[0]["graph_reachable"] is None
    assert {call["tenant_id"] for call in empty.calls} == {"tenant-b"}
