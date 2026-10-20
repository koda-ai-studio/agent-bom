"""One reachability verdict per finding, shared by the list, filter, facets and paths."""

from __future__ import annotations

import pytest

from agent_bom.api import finding_reachability
from agent_bom.api.finding_facets import _facet_reachability_bucket
from agent_bom.api.finding_reachability import project_persisted_graph_reachability
from agent_bom.api.finding_view_filters import _matches_reachability
from agent_bom.core.reachability import finding_reachability as derive_finding_reachability
from agent_bom.core.reachability import reachability_bucket
from agent_bom.graph import AttackPath


class _Store:
    def __init__(self, paths: list[AttackPath]) -> None:
        self.paths = paths

    def attack_paths(self, **kwargs):
        offset, limit = int(kwargs["offset"]), int(kwargs["limit"])
        return "current-estate:abc", "2026-10-19T00:00:00Z", self.paths[offset : offset + limit], len(self.paths)


def _path(*, reachability: str = "likely", basis: list[str] | None = None, index: int = 1) -> AttackPath:
    cve = f"CVE-2026-{index:05d}"
    return AttackPath(
        source="agent:a",
        target=f"vuln:{cve}",
        hops=["agent:a", "server:s", "pkg:p", f"vuln:{cve}"],
        edges=["uses", "depends_on", "vulnerable_to"],
        finding_ids=[f"occurrence-{index}"],
        vuln_ids=[cve],
        reachability=reachability,
        reachability_basis=basis if basis is not None else ["graph_path", "directed_provenance_backed_hops"],
    )


def _row(**overrides) -> dict:
    row = {"id": "occurrence-1", "cve_id": "CVE-2026-00001", "reachability": "unknown", "evidence": {"match_confidence_tier": "osv_range"}}
    row.update(overrides)
    return row


def _project(rows: list[dict], paths: list[AttackPath]) -> list[dict]:
    finding_reachability.clear_reachability_index_cache()
    return project_persisted_graph_reachability(rows, graph_store=_Store(paths), tenant_id="t", scan_id=None).rows  # type: ignore[arg-type]


def test_stamped_graph_path_rederives_a_stale_unknown_verdict_to_likely():
    [row] = _project([_row()], [_path()])

    assert row["graph_reachable"] is True
    assert row["reachability"] == "likely"


def test_a_graph_path_alone_is_never_confirmed():
    [row] = _project([_row(reachability="confirmed")], [_path(reachability="confirmed", basis=["graph_path"])])

    assert row["reachability"] == "likely"


def test_function_level_evidence_confirms_a_reached_finding():
    [row] = _project([_row(evidence={"symbol_reachability": "function_reachable"})], [_path()])

    assert row["reachability"] == "confirmed"


def test_runtime_observed_path_confirms():
    [row] = _project([_row()], [_path(reachability="confirmed", basis=["runtime_observed"])])

    assert row["reachability"] == "confirmed"


def test_negative_symbol_evidence_still_wins_over_a_graph_path():
    [row] = _project([_row(evidence={"symbol_reachability": "unreachable"})], [_path()])

    assert row["graph_reachable"] is True
    assert row["reachability"] == "unlikely"


def test_unverified_advisory_match_stays_unknown_even_with_a_path():
    [row] = _project([_row(evidence={"match_confidence_tier": "nvd_cpe_candidate"})], [_path()])

    assert row["reachability"] == "unknown"


def test_only_unverified_paths_do_not_lift_the_verdict():
    [row] = _project([_row()], [_path(reachability="unknown", basis=["stale_hop_evidence"])])

    assert row["graph_reachable"] is True
    assert row["reachability"] == "unknown"


def test_never_assessed_rows_keep_a_null_verdict():
    [row] = _project([{"id": "misconfig-1", "finding_type": "CLOUD_MISCONFIG"}], [_path()])

    assert row.get("reachability") is None


@pytest.mark.parametrize(
    ("row", "bucket"),
    [
        ({"graph_reachable": True, "reachability": "unknown"}, "reachable"),
        ({"graph_reachable": False, "reachability": "likely"}, "unreachable"),
        ({"graph_reachable": None}, "unassessed"),
        ({"graph_reachable": True, "evidence": {"symbol_reachability": "unreachable"}}, "unreachable"),
        ({"graph_reachable": True, "evidence": {"match_confidence_tier": "nvd_cpe_candidate"}}, "unassessed"),
        ({"evidence": {"symbol_reachability": "function_reachable"}}, "reachable"),
    ],
)
def test_filter_facets_and_displayed_verdict_share_one_bucket(row: dict, bucket: str):
    verdict = derive_finding_reachability(row)
    displayed = verdict.verdict.value if verdict is not None else None

    assert reachability_bucket(row) == bucket
    assert _facet_reachability_bucket(row) == bucket
    assert _matches_reachability(row, bucket)
    expected = {"reachable": {"confirmed", "likely"}, "unreachable": {"unlikely"}, "unassessed": {"unknown", None}}[bucket]
    assert displayed in expected


def test_projected_page_filter_and_verdict_agree_row_by_row():
    rows = [
        _row(id="occurrence-1"),
        _row(id="occurrence-2", cve_id="CVE-2026-00002", evidence={"symbol_reachability": "unreachable"}),
        _row(id="occurrence-3", cve_id="CVE-2026-00003"),
    ]
    paths = [_path(), _path(index=2)]

    projected = _project(rows, paths)
    reachable = [row for row in projected if _matches_reachability(row, "reachable")]

    assert {row["id"] for row in reachable} == {"occurrence-1"}
    assert all(row["reachability"] in {"likely", "confirmed"} for row in reachable)
