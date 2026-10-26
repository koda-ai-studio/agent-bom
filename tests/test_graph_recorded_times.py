"""Graph times are the recorded scan/snapshot time, never the wall clock at build.

The same input must produce the same graph on every build: a node or edge with
no explicit time takes its graph's ``created_at``, and builders with a real
record time pass it. Each invariant builds twice with the wall clock pinned to
two different sentinels and asserts the graphs match and hold neither sentinel.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from agent_bom.graph import util as graph_util
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.recorded_time import normalize_recorded_time
from agent_bom.graph.types import EntityType, RelationshipType

SENTINEL_A = "1999-01-01T00:00:00+00:00"
SENTINEL_B = "2099-12-31T23:59:59+00:00"
RECORDED = "2026-10-01T12:00:00+00:00"


@contextmanager
def _clock(value: str) -> Iterator[None]:
    """Pin every module-level ``_now_iso`` the graph package imported from graph.util."""
    original = graph_util._now_iso
    patched = [
        mod
        for name, mod in list(sys.modules.items())
        if name.startswith("agent_bom") and getattr(mod, "__dict__", {}).get("_now_iso") is original
    ]
    assert len(patched) >= 4
    for mod in patched:
        setattr(mod, "_now_iso", lambda: value)
    try:
        yield
    finally:
        for mod in patched:
            setattr(mod, "_now_iso", original)


def _build_payload(build: Callable[[], UnifiedGraph], clock: str) -> Any:
    with _clock(clock):
        return json.loads(json.dumps(build().to_dict(), default=str))


def _differences(a: Any, b: Any, path: str = "$") -> Iterator[str]:
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b), key=str):
            yield from _differences(a.get(key), b.get(key), f"{path}.{key}")
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for index, (left, right) in enumerate(zip(a, b)):
            label = left.get("id", index) if isinstance(left, dict) else index
            yield from _differences(left, right, f"{path}[{label}]")
    elif a != b:
        yield f"{path}: {str(a)[:80]!r} != {str(b)[:80]!r}"


def _sentinel_paths(value: Any, path: str = "$") -> Iterator[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _sentinel_paths(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _sentinel_paths(item, f"{path}[{index}]")
    elif isinstance(value, str) and (SENTINEL_A in value or SENTINEL_B in value):
        yield path


def _assert_deterministic(build: Callable[[], UnifiedGraph]) -> None:
    first = _build_payload(build, SENTINEL_A)
    second = _build_payload(build, SENTINEL_B)
    leaked = [*_sentinel_paths(first), *_sentinel_paths(second)]
    assert not leaked, f"{len(leaked)} wall-clock times leaked, e.g. {leaked[:10]}"
    differences = list(_differences(first, second))
    assert not differences, f"{len(differences)} differences between builds, e.g. {differences[:10]}"


def test_untimed_node_and_edge_take_the_graph_recorded_time() -> None:
    with _clock(SENTINEL_A):
        graph = UnifiedGraph(scan_id="s", created_at=RECORDED)
        graph.add_node(UnifiedNode(id="a", entity_type=EntityType.AGENT, label="a"))
        graph.add_node(UnifiedNode(id="b", entity_type=EntityType.SERVER, label="b"))
        graph.add_edge(UnifiedEdge(source="a", target="b", relationship=RelationshipType.USES, direction="bidirectional"))
    for node in graph.nodes.values():
        assert (node.first_seen, node.last_seen) == (RECORDED, RECORDED)
    for edge in [*graph.edges, *graph.adjacency["b"]]:
        assert (edge.first_seen, edge.last_seen, edge.valid_from) == (RECORDED, RECORDED, RECORDED)


def test_explicit_times_are_kept_and_merge_keeps_the_observed_span() -> None:
    graph = UnifiedGraph(scan_id="s", created_at=RECORDED)
    graph.add_node(UnifiedNode(id="a", entity_type=EntityType.AGENT, label="a", first_seen="2026-09-01T00:00:00+00:00"))
    graph.add_node(UnifiedNode(id="a", entity_type=EntityType.AGENT, label="a", first_seen="2026-08-01T00:00:00+00:00"))
    with _clock(SENTINEL_B):
        graph.add_node(UnifiedNode(id="a", entity_type=EntityType.AGENT, label="a"))
    node = graph.nodes["a"]
    assert node.first_seen == "2026-08-01T00:00:00+00:00"
    assert node.last_seen == RECORDED


def test_only_last_seen_given_does_not_invent_an_earlier_clock_time() -> None:
    with _clock(SENTINEL_B):
        node = UnifiedNode(id="a", entity_type=EntityType.AGENT, label="a", last_seen="2026-09-01T00:00:00+00:00")
    assert node.first_seen == "2026-09-01T00:00:00+00:00"


def test_snapshot_round_trip_keeps_stored_times() -> None:
    graph = UnifiedGraph(scan_id="s", created_at=RECORDED)
    graph.add_node(UnifiedNode(id="a", entity_type=EntityType.AGENT, label="a", first_seen="2026-09-01T00:00:00+00:00"))
    graph.add_node(UnifiedNode(id="b", entity_type=EntityType.SERVER, label="b"))
    graph.add_edge(UnifiedEdge(source="a", target="b", relationship=RelationshipType.USES))
    with _clock(SENTINEL_B):
        restored = UnifiedGraph.from_dict(graph.to_dict())
    assert restored.created_at == RECORDED

    def times(payload: dict[str, Any]) -> list[tuple[str, ...]]:
        rows = [*payload["nodes"], *payload["edges"]]
        return [(row["id"], row["first_seen"], row["last_seen"], row.get("valid_from", "")) for row in rows]

    assert times(restored.to_dict()) == times(graph.to_dict())


def test_stored_row_without_times_reads_back_at_the_snapshot_time() -> None:
    payload = UnifiedGraph(scan_id="s", created_at=RECORDED).to_dict()
    payload["nodes"] = [{"id": "a", "entity_type": "agent", "label": "a"}]
    with _clock(SENTINEL_B):
        restored = UnifiedGraph.from_dict(payload)
    assert restored.nodes["a"].first_seen == RECORDED


@pytest.fixture(scope="module")
def demo_report(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    from agent_bom.cli import main

    out = Path(tmp_path_factory.mktemp("recorded-times")) / "report.json"
    CliRunner().invoke(main, ["scan", "--offline", "--demo", "-f", "json", "-q", "-o", str(out)])
    assert out.is_file()
    report = json.loads(out.read_text())
    assert report.get("generated_at")
    return report


def test_report_graph_is_identical_across_builds(demo_report: dict[str, Any]) -> None:
    from agent_bom.graph.builder import build_unified_graph_from_report

    def build() -> UnifiedGraph:
        return build_unified_graph_from_report(demo_report, scan_id="recorded-times")

    _assert_deterministic(build)
    graph = build()
    assert len(graph.nodes) > 20 and graph.edges
    assert graph.created_at == normalize_recorded_time(demo_report["generated_at"])


def test_demo_estate_graph_is_identical_across_builds() -> None:
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_CURRENT_CREATED_AT, build_demo_identity_store, build_showcase_snapshot

    # The identity store is live input seeded relative to boot so demo grants stay
    # current; hold it fixed so the comparison isolates what the graph code stamps.
    identities = build_demo_identity_store()

    def build() -> UnifiedGraph:
        return build_showcase_snapshot(profile="current", identity_records=identities)

    assert build().created_at == SHOWCASE_CURRENT_CREATED_AT
    _assert_deterministic(build)


def test_finding_rows_carry_their_recorded_observation_time(demo_report: dict[str, Any]) -> None:
    from agent_bom.evidence.finding_node_ids import finding_row_node_id
    from agent_bom.graph.builder import build_unified_graph_from_report

    report = json.loads(json.dumps(demo_report))
    rows = [row for row in report["findings"] if finding_row_node_id(row)]
    assert rows
    for row in rows:
        row["first_seen"] = "2026-01-02T03:04:05+00:00"
    graph = build_unified_graph_from_report(report, scan_id="recorded-times")
    stamped = [graph.nodes[node_id] for node_id in {str(finding_row_node_id(row)) for row in rows} if node_id in graph.nodes]
    assert stamped
    assert {node.first_seen for node in stamped} == {"2026-01-02T03:04:05+00:00"}


def test_cloud_audit_edges_carry_the_aggregate_observation_time() -> None:
    from agent_bom.graph.builder import build_unified_graph_from_report

    observed = "2026-08-03T18:00:00Z"
    report = {
        "generated_at": RECORDED,
        "cloud_audit_trail": {
            "status": "ok",
            "provider": "aws",
            "account": "111122223333",
            "behavioral_edges": [{"principal": "operator", "resource": "bucket-a", "action": "GetObject", "count": 2, "last_seen": observed}],
        },
    }
    with _clock(SENTINEL_B):
        graph = build_unified_graph_from_report(report, scan_id="audit")
    observed_edges = [edge for edge in graph.edges if edge.evidence.get("observed")]
    assert observed_edges
    assert {(edge.first_seen, edge.last_seen) for edge in observed_edges} == {(observed, observed)}
