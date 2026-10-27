"""The reachability join derives each path's identifiers once per index, not once per row.

Facet counts stream every in-scope finding through this join under a wall-clock
deadline. Re-deriving a shared CVE's paths for every occurrence made a
2,700-row demo estate need most of that deadline, so a loaded runner returned a
severity facet that was a lower bound of its own total.
"""

from __future__ import annotations

from agent_bom.api import finding_reachability as fr
from agent_bom.graph.container import AttackPath

_PATHS = 40
_ROWS = 300


def _paths() -> list[AttackPath]:
    return [
        AttackPath(
            source=f"agent:a{i}",
            target="vuln:CVE-2026-0001",
            hops=[f"agent:a{i}", f"server:s{i}", f"pkg:p{i % 7}", "vuln:CVE-2026-0001"],
            edges=["uses", "depends_on", "vulnerable_to"],
            vuln_ids=["CVE-2026-0001"],
            reachability="likely",
        )
        for i in range(_PATHS)
    ]


def _rows() -> list[dict]:
    return [{"id": f"f-{i}", "cve_id": "cve-2026-0001", "node_id": f"pkg:p{i % 9}", "scan_id": "s"} for i in range(_ROWS)]


def _naive_stamp(rows: list[dict], paths: list[AttackPath]) -> list[dict]:
    """The pre-index semantics: every row tested against every evidence-bearing path."""
    out = [dict(row) for row in rows]
    for row in out:
        holders = fr._row_node_ids(row)
        matched = [p for p in paths if fr._path_has_reachability_evidence(p) and p.source not in holders and fr._path_matches_row(p, row)]
        row["expected_reachable"] = bool(matched)
        row["expected_hops"] = min((fr._path_hop_distance(p, row) for p in matched), default=None)
        row["expected_agents"] = sorted({a for p in matched for a in fr._reaching_agents(p)})
    return out


def test_path_identifiers_are_derived_once_per_path(monkeypatch) -> None:
    calls = {"count": 0}
    original = fr._path_vulnerability_ids

    def counting(path: AttackPath) -> set[str]:
        calls["count"] += 1
        return original(path)

    monkeypatch.setattr(fr, "_path_vulnerability_ids", counting)
    rows = _rows()
    fr.project_attack_path_reachability(rows, _paths())
    assert calls["count"] <= _PATHS, f"{calls['count']} path derivations for {_PATHS} paths and {_ROWS} rows"


def test_indexed_join_matches_testing_every_path() -> None:
    paths = _paths()
    rows = _rows()
    expected = _naive_stamp(rows, paths)
    fr.project_attack_path_reachability(rows, paths)
    assert any(row["expected_reachable"] for row in expected)
    assert any(not row["expected_reachable"] for row in expected)
    for row, want in zip(rows, expected):
        assert bool(row.get("graph_reachable")) == want["expected_reachable"], row["id"]
        if want["expected_reachable"]:
            assert row["graph_min_hop_distance"] == want["expected_hops"], row["id"]
            assert row["graph_reachable_from_agents"] == want["expected_agents"], row["id"]
