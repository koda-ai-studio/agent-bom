"""CIS check rows whose failing results come from the tenant's current graph.

A failed benchmark control is one graph node (``misconfig:<section>:<check>``)
with an ``affects`` edge to every failing resource; an unevaluable one is a
``CIS_ERROR`` finding node. Stored benchmark blobs are an older, flatter copy of
the same result, so when the graph holds CIS evidence for a cloud its failing
rows and resources are what ``/v1/cis/checks`` and the scorecard report. Stored
rows keep what the graph cannot hold: recorded passes, not-applicable results
and remediation metadata.

A check is ``pass`` only when a scan recorded a passing result. A stored failure
the current graph no longer holds has no recorded pass behind it, so it becomes
``not_evaluated`` — never an implied pass.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from agent_bom.evidence.finding_node_ids import _BENCHMARK_SECTIONS
from agent_bom.security import sanitize_text

_logger = logging.getLogger(__name__)

RECORDED_CIS_STATUSES = frozenset({"pass", "fail", "error", "not_applicable"})
NOT_EVALUATED = "not_evaluated"
_SECTION_CLOUDS = {section: cloud for cloud, section in _BENCHMARK_SECTIONS.items()}
_ERROR_FINDING_TYPES = frozenset({"CIS_ERROR", "CLOUD_BEST_PRACTICE_ERROR"})
_OUTCOME_PREFIX = re.compile(r"^(?:Failed|Unevaluated) (?:CIS|Databricks best practice) \S+ — ")
# A tenant's CIS nodes are one per failed check plus one per unevaluable
# resource. Past this bound the read is partial and must not overrule stored rows.
GRAPH_CIS_NODE_BUDGET = 20_000
_PAGE = 2_000


def normalize_cis_status(status: object) -> str:
    """Map a stored status onto the recorded vocabulary; anything else was not evaluated."""
    value = str(status or "").strip().lower()
    return value if value in RECORDED_CIS_STATUSES else NOT_EVALUATED


@dataclass(frozen=True)
class GraphCisCheck:
    cloud: str
    check_id: str
    status: str
    title: str
    severity: str
    cis_section: str
    node_id: str
    resource_ids: tuple[str, ...]
    unevaluated_resource_ids: tuple[str, ...]
    finding_ids: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphCisState:
    scan_id: str
    checks: dict[tuple[str, str], GraphCisCheck]
    complete: bool

    @classmethod
    def empty(cls) -> GraphCisState:
        return cls(scan_id="", checks={}, complete=True)

    @property
    def clouds(self) -> frozenset[str]:
        return frozenset(cloud for cloud, _ in self.checks)


@dataclass
class _Accumulator:
    cloud: str
    check_id: str
    title: str = ""
    severity: str = ""
    cis_section: str = ""
    fail_node: str = ""
    error_nodes: list[str] = field(default_factory=list)
    finding_ids: dict[str, list[str]] = field(default_factory=dict)


def _strip_check_prefix(value: object) -> str:
    text = str(value or "").strip()
    return text[4:] if text.upper().startswith("CIS-") else text


def _classify(node: Any) -> tuple[str, str, bool] | None:
    """Return ``(cloud, check_id, failed)`` for a CIS result node, else ``None``."""
    section, _, check_id = str(node.id).removeprefix("misconfig:").partition(":")
    if str(node.id).startswith("misconfig:") and section in _SECTION_CLOUDS and check_id:
        return _SECTION_CLOUDS[section], check_id, True
    attributes = node.attributes or {}
    if str(attributes.get("finding_type") or "") in _ERROR_FINDING_TYPES:
        cloud = str(attributes.get("cloud_provider") or "").lower()
        check = _strip_check_prefix(attributes.get("check_id"))
        if cloud in _BENCHMARK_SECTIONS and check:
            return cloud, check, False
    return None


def _absorb(acc: _Accumulator, node: Any, failed: bool) -> None:
    attributes = node.attributes or {}
    if failed:
        acc.fail_node = node.id
        acc.title = _OUTCOME_PREFIX.sub("", str(node.label or "")) or acc.check_id
        acc.severity = str(node.severity or "unknown").lower()
        acc.cis_section = str(attributes.get("cis_section") or "")
        for asset, ids in (attributes.get("finding_ids_by_asset") or {}).items():
            acc.finding_ids[str(asset)] = sorted({str(item) for item in ids or []})
        return
    acc.error_nodes.append(node.id)
    if not acc.title:
        acc.title = _OUTCOME_PREFIX.sub("", str(node.label or "")) or acc.check_id
        acc.cis_section = str(attributes.get("cis_section") or "")


def graph_cis_state_from_nodes(nodes: Iterable[Any], edges: Iterable[Any], *, scan_id: str, complete: bool) -> GraphCisState:
    """Fold CIS result nodes and their ``affects`` edges into one row per check."""
    accumulators: dict[tuple[str, str], _Accumulator] = {}
    owner: dict[str, tuple[tuple[str, str], bool]] = {}
    for node in nodes:
        classified = _classify(node)
        if classified is None:
            continue
        cloud, check_id, failed = classified
        key = (cloud, check_id)
        acc = accumulators.setdefault(key, _Accumulator(cloud=cloud, check_id=check_id))
        _absorb(acc, node, failed)
        owner[node.id] = (key, failed)
    targets: dict[tuple[tuple[str, str], bool], set[str]] = defaultdict(set)
    for edge in edges:
        relationship = getattr(edge.relationship, "value", edge.relationship)
        if relationship == "affects" and edge.source in owner:
            targets[owner[edge.source]].add(str(edge.target))
    checks = {key: _check_from(acc, targets) for key, acc in accumulators.items()}
    return GraphCisState(scan_id=scan_id, checks=checks, complete=complete)


def _check_from(acc: _Accumulator, targets: dict[tuple[tuple[str, str], bool], set[str]]) -> GraphCisCheck:
    key = (acc.cloud, acc.check_id)
    failing = targets.get((key, True), set()) | set(acc.finding_ids)
    unevaluated = targets.get((key, False), set()) - failing
    return GraphCisCheck(
        cloud=acc.cloud,
        check_id=acc.check_id,
        status="fail" if acc.fail_node else "error",
        title=acc.title or acc.check_id,
        severity=acc.severity or "unknown",
        cis_section=acc.cis_section,
        node_id=acc.fail_node or sorted(acc.error_nodes)[0],
        resource_ids=tuple(sorted(failing)),
        unevaluated_resource_ids=tuple(sorted(unevaluated)),
        finding_ids={asset: ids for asset, ids in sorted(acc.finding_ids.items()) if asset in failing},
    )


def read_graph_cis_state(graph_store: Any, tenant_id: str) -> GraphCisState:
    """Read the current snapshot's CIS result nodes; any failure reads as no graph evidence."""
    try:
        return _read_graph_cis_state(graph_store, tenant_id)
    except Exception as exc:  # broad-except: any graph read failure leaves the stored rows as the answer
        _logger.warning("graph CIS evidence unavailable: %s", sanitize_text(exc))
        return GraphCisState.empty()


def _read_graph_cis_state(graph_store: Any, tenant_id: str) -> GraphCisState:
    page_nodes = getattr(graph_store, "page_nodes", None)
    if graph_store is None or not callable(page_nodes):
        return GraphCisState.empty()
    scan_id, cursor, read, total = "", None, 0, 0
    nodes: list[Any] = []
    while True:
        scan_id, _created, page, total, cursor = page_nodes(
            tenant_id=tenant_id, scan_id=scan_id, entity_types={"misconfiguration"}, cursor=cursor, limit=_PAGE
        )
        read += len(page)
        nodes.extend(node for node in page if _classify(node) is not None)
        if not cursor or not page or read >= GRAPH_CIS_NODE_BUDGET:
            break
    if not nodes:
        return GraphCisState.empty()
    edges = graph_store.edges_for_node_ids(
        tenant_id=tenant_id, scan_id=scan_id, node_ids={node.id for node in nodes}, direction="out", relationships={"affects"}
    )
    return graph_cis_state_from_nodes(nodes, edges, scan_id=scan_id, complete=read >= int(total or 0))


def _graph_row(check: GraphCisCheck, base: dict[str, Any] | None, scan_id: str) -> dict[str, Any]:
    row = dict(base or {})
    unevaluated = len(check.unevaluated_resource_ids)
    evidence = f"{len(check.resource_ids)} resource(s) fail this control in the current graph."
    if check.status == "error":
        evidence = f"{unevaluated} resource(s) could not be evaluated for this control in the current graph."
    elif unevaluated:
        evidence += f" {unevaluated} more could not be evaluated."
    row.update(
        cloud=check.cloud,
        check_id=check.check_id,
        title=check.title,
        status=check.status,
        severity=check.severity if check.status == "fail" else str(row.get("severity") or check.severity),
        cis_section=check.cis_section or str(row.get("cis_section") or ""),
        evidence=evidence,
        resource_ids=list(check.resource_ids),
        unevaluated_resource_ids=list(check.unevaluated_resource_ids),
        resource_finding_ids=dict(check.finding_ids),
        graph_node_id=check.node_id,
        graph_scan_id=scan_id,
        evidence_source="graph",
    )
    row.setdefault("scan_id", scan_id)
    row.setdefault("measured_at", "")
    row.setdefault("benchmark_version", "")
    row.setdefault("remediation", {})
    row.setdefault("priority", 0)
    return row


def _stored_row(row: dict[str, Any], state: GraphCisState) -> dict[str, Any]:
    stored = {**row, "status": normalize_cis_status(row.get("status")), "evidence_source": "scan"}
    superseded = state.complete and str(row.get("cloud") or "") in state.clouds
    if superseded and stored["status"] == "fail":
        # The graph is the current result for this cloud and no longer holds this
        # failure; nothing recorded a pass since, so the honest state is unknown.
        stored.update(
            status=NOT_EVALUATED,
            resource_ids=[],
            evidence=f"The failure recorded by scan {row.get('scan_id') or 'unknown'} is not in the current graph, "
            "and no passing result has been recorded since.",
        )
    return stored


def merge_cis_rows_with_graph(rows: Iterable[dict[str, Any]], state: GraphCisState) -> list[dict[str, Any]]:
    """Latest stored row per check, with graph results replacing the failing ones."""
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        key = (str(row.get("cloud") or ""), str(row.get("check_id") or ""))
        check = state.checks.get(key)
        merged.append(_graph_row(check, row, state.scan_id) if check is not None else _stored_row(row, state))
        seen.add(key)
    for key, check in sorted(state.checks.items()):
        if key not in seen:
            merged.append(_graph_row(check, None, state.scan_id))
    return merged


__all__ = [
    "GRAPH_CIS_NODE_BUDGET",
    "GraphCisCheck",
    "GraphCisState",
    "NOT_EVALUATED",
    "RECORDED_CIS_STATUSES",
    "graph_cis_state_from_nodes",
    "merge_cis_rows_with_graph",
    "normalize_cis_status",
    "read_graph_cis_state",
]
