"""CIS check rows take their failing results from the current graph.

A failing CIS control is evidence on the graph: one node per failed check with
an ``affects`` edge to every failing resource. ``/v1/cis/checks`` and the
compliance scorecard used to read only stored benchmark blobs, so the panel and
the graph could disagree about which controls fail and on which resources.
"""

from __future__ import annotations

from typing import Any

from agent_bom.api.cis_graph_checks import (
    GraphCisState,
    graph_cis_state_from_nodes,
    merge_cis_rows_with_graph,
    normalize_cis_status,
)
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _fail_node(section: str, check_id: str, provider: str, *, finding_ids: dict[str, list[str]] | None = None) -> UnifiedNode:
    return UnifiedNode(
        id=f"misconfig:{section}:{check_id}",
        entity_type=EntityType.MISCONFIGURATION,
        label=f"Failed CIS {check_id} — control {check_id}",
        severity="high",
        attributes={
            "check_id": f"CIS-{check_id}",
            "cloud_provider": provider,
            "cis_section": "2 - Storage",
            "finding_type": "CIS_FAIL",
            "finding_ids_by_asset": finding_ids or {},
        },
    )


def _error_node(node_id: str, check_id: str, provider: str) -> UnifiedNode:
    return UnifiedNode(
        id=node_id,
        entity_type=EntityType.MISCONFIGURATION,
        label=f"Unevaluated CIS {check_id} — control {check_id}",
        severity="unknown",
        attributes={"check_id": f"CIS-{check_id}", "cloud_provider": provider, "finding_type": "CIS_ERROR"},
    )


def _affects(source: str, target: str) -> UnifiedEdge:
    return UnifiedEdge(source=source, target=target, relationship=RelationshipType.AFFECTS)


def _row(cloud: str, check_id: str, status: str, resource_ids: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    return {
        "scan_id": "scan-1",
        "measured_at": "2026-10-20T00:00:00+00:00",
        "cloud": cloud,
        "benchmark_version": "3.0.0",
        "check_id": check_id,
        "title": f"title {check_id}",
        "status": status,
        "severity": "medium",
        "cis_section": "",
        "evidence": "",
        "resource_ids": resource_ids or [],
        "remediation": {},
        "priority": 3,
        **extra,
    }


def test_graph_state_reads_failures_resources_and_finding_ids() -> None:
    nodes = [
        _fail_node("cis_benchmark", "2.1.1", "aws", finding_ids={"aws:bucket:a": ["f-1"]}),
        _fail_node("snowflake_cis_benchmark", "3.1", "snowflake"),
        _error_node("misconfig:cloud_cis:e1", "5.1", "snowflake"),
        # Not CIS: IaC and generic misconfigurations stay out of the CIS view.
        UnifiedNode(id="misconfig:iac:r:f:1", entity_type=EntityType.MISCONFIGURATION, label="iac"),
    ]
    edges = [
        _affects("misconfig:cis_benchmark:2.1.1", "aws:bucket:a"),
        _affects("misconfig:cis_benchmark:2.1.1", "aws:bucket:b"),
        _affects("misconfig:snowflake_cis_benchmark:3.1", "snowflake:table:t"),
        _affects("misconfig:cloud_cis:e1", "snowflake:role:r"),
    ]

    state = graph_cis_state_from_nodes(nodes, edges, scan_id="scan-g", complete=True)

    assert state.clouds == frozenset({"aws", "snowflake"})
    aws = state.checks[("aws", "2.1.1")]
    assert aws.status == "fail"
    assert aws.node_id == "misconfig:cis_benchmark:2.1.1"
    assert aws.resource_ids == ("aws:bucket:a", "aws:bucket:b")
    assert aws.finding_ids == {"aws:bucket:a": ["f-1"]}
    assert state.checks[("snowflake", "3.1")].resource_ids == ("snowflake:table:t",)
    unevaluated = state.checks[("snowflake", "5.1")]
    assert unevaluated.status == "error"
    assert unevaluated.unevaluated_resource_ids == ("snowflake:role:r",)


def test_failing_rows_and_resources_come_from_the_graph() -> None:
    state = graph_cis_state_from_nodes(
        [_fail_node("cis_benchmark", "2.1.1", "aws", finding_ids={"aws:bucket:a": ["f-1"]})],
        [_affects("misconfig:cis_benchmark:2.1.1", "aws:bucket:a")],
        scan_id="scan-g",
        complete=True,
    )
    rows = [
        # Older numbering said 2.1.1 passed on another resource; the graph is the current result.
        _row("aws", "2.1.1", "pass", ["customer-pii-prod"], fix_console="S3 > Permissions"),
        _row("aws", "1.4", "pass", ["root"]),
    ]

    merged = {row["check_id"]: row for row in merge_cis_rows_with_graph(rows, state)}

    failing = merged["2.1.1"]
    assert failing["status"] == "fail"
    assert failing["resource_ids"] == ["aws:bucket:a"]
    assert failing["resource_finding_ids"] == {"aws:bucket:a": ["f-1"]}
    assert failing["graph_node_id"] == "misconfig:cis_benchmark:2.1.1"
    assert failing["evidence_source"] == "graph"
    assert failing["title"] == "control 2.1.1", "the graph's control title, not a stale stored one"
    assert failing["fix_console"] == "S3 > Permissions", "remediation metadata from the stored row is kept"
    # A recorded pass the graph does not contradict stays a pass.
    assert merged["1.4"]["status"] == "pass"
    assert merged["1.4"]["evidence_source"] == "scan"


def test_graph_failure_without_a_stored_row_is_still_listed() -> None:
    state = graph_cis_state_from_nodes(
        [_fail_node("snowflake_cis_benchmark", "1.4", "snowflake")],
        [_affects("misconfig:snowflake_cis_benchmark:1.4", "snowflake:role:accountadmin")],
        scan_id="scan-g",
        complete=True,
    )

    merged = merge_cis_rows_with_graph([], state)

    assert [(row["cloud"], row["check_id"], row["status"]) for row in merged] == [("snowflake", "1.4", "fail")]
    assert merged[0]["resource_ids"] == ["snowflake:role:accountadmin"]
    assert merged[0]["title"] == "control 1.4"
    assert merged[0]["severity"] == "high"


def test_stored_failure_absent_from_the_graph_is_not_evaluated_never_pass() -> None:
    state = graph_cis_state_from_nodes([_fail_node("cis_benchmark", "2.1.1", "aws")], [], scan_id="scan-g", complete=True)
    rows = [_row("aws", "4.1", "fail", ["sg-prod"]), _row("gcp", "3.6", "fail", ["allow-ssh"])]

    merged = {(row["cloud"], row["check_id"]): row for row in merge_cis_rows_with_graph(rows, state)}

    stale = merged[("aws", "4.1")]
    assert stale["status"] == "not_evaluated"
    assert stale["resource_ids"] == []
    # A cloud the graph holds no CIS evidence for keeps its stored result.
    assert merged[("gcp", "3.6")]["status"] == "fail"


def test_an_incomplete_graph_read_never_downgrades_a_stored_failure() -> None:
    state = graph_cis_state_from_nodes([_fail_node("cis_benchmark", "2.1.1", "aws")], [], scan_id="scan-g", complete=False)

    merged = {row["check_id"]: row for row in merge_cis_rows_with_graph([_row("aws", "4.1", "fail", ["sg-prod"])], state)}

    assert merged["4.1"]["status"] == "fail"


def test_unknown_or_missing_status_is_not_evaluated() -> None:
    assert normalize_cis_status("PASS") == "pass"
    assert normalize_cis_status("not_applicable") == "not_applicable"
    for raw in ("", "unknown", None, "skipped", "manual"):
        assert normalize_cis_status(raw) == "not_evaluated", raw


def test_empty_graph_state_leaves_rows_unchanged_apart_from_status_vocabulary() -> None:
    rows = [_row("aws", "1.4", "pass"), _row("aws", "1.5", "unknown")]

    merged = merge_cis_rows_with_graph(rows, GraphCisState.empty())

    assert [row["status"] for row in merged] == ["pass", "not_evaluated"]
