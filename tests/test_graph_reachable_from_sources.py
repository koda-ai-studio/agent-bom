"""``graph_reachable_from`` is server-stamped path-source evidence for any inbound path."""

from __future__ import annotations

from agent_bom.api.bulk_findings_ingest import _normalized_bulk_finding
from agent_bom.api.compliance_hub_store import _redact_finding
from agent_bom.api.finding_reachability import clear_reachability_index_cache, project_persisted_graph_reachability
from agent_bom.finding_scope import safe_finding_response_payload
from agent_bom.graph import AttackPath

_WORKLOAD = "kubernetes:workload:prod/payments/api-0"


def _row(**extra: object) -> dict:
    return {"id": "occ-1", "cve_id": "CVE-2026-0001", "severity": "high", **extra}


class _Store:
    def __init__(self, paths: list[AttackPath]) -> None:
        self.paths = paths

    def attack_paths(self, **kwargs):
        offset, limit = int(kwargs["offset"]), int(kwargs["limit"])
        return "current-estate:x", "2026-10-19T00:00:00Z", self.paths[offset : offset + limit], len(self.paths)


def _workload_path(index: int = 0) -> AttackPath:
    return AttackPath(
        source=f"{_WORKLOAD}-{index}",
        target="vuln:CVE-2026-0001",
        hops=[f"{_WORKLOAD}-{index}", "pkg:pypi:pillow@9.0.0", "vuln:CVE-2026-0001"],
        edges=["depends_on", "vulnerable_to"],
        finding_ids=["occ-1"],
        vuln_ids=["CVE-2026-0001"],
    )


def setup_function() -> None:
    clear_reachability_index_cache()


def test_projection_stamps_bounded_path_sources_and_count():
    store = _Store([_workload_path(i) for i in range(25)])
    row = project_persisted_graph_reachability([_row()], graph_store=store, tenant_id="t", scan_id=None).rows[0]  # type: ignore[arg-type]
    assert row["graph_reachable"] is True
    assert row["graph_reachable_from_agents"] == []
    assert row["graph_reachable_from_count"] == 25
    assert len(row["graph_reachable_from"]) == 20
    assert row["graph_reachable_from"] == sorted(row["graph_reachable_from"])


def test_response_accepts_a_workload_only_path_with_server_stamped_sources():
    store = _Store([_workload_path()])
    stamped = project_persisted_graph_reachability([_row()], graph_store=store, tenant_id="t", scan_id=None).rows[0]  # type: ignore[arg-type]
    payload = safe_finding_response_payload(stamped)
    assert payload["graph_reachable"] is True
    assert payload["graph_reachable_from"] == [f"{_WORKLOAD}-0"]
    assert payload["graph_reachable_from_count"] == 1


def test_response_still_nulls_an_uncorroborated_claim():
    payload = safe_finding_response_payload(_row(graph_reachable=True, graph_min_hop_distance=3))
    assert payload["graph_reachable"] is None
    assert payload["graph_reachable_from"] == []


def test_forged_sources_on_persistence_are_stripped_and_the_claim_nulled():
    stored = _redact_finding(_row(graph_reachable=True, graph_reachable_from=["attacker:anything"], graph_reachable_from_count=1))
    assert "graph_reachable_from" not in stored
    assert "graph_reachable_from_count" not in stored
    assert stored.get("graph_reachable") is None


def test_pushed_bulk_finding_cannot_claim_reachability():
    pushed = _row(graph_reachable=True, graph_reachable_from=["attacker:x"], graph_reachable_from_agents=["agent:forged"])
    normalized = _normalized_bulk_finding(pushed, source="push", batch_id="b", ordinal=0)
    assert not {"graph_reachable_from", "graph_reachable_from_agents", "graph_reachable_from_count"} & normalized.keys()
    assert _redact_finding(normalized).get("graph_reachable") is None
