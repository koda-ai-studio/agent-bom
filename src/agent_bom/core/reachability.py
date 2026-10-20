"""Canonical reachability truth used across findings and attack paths.

Structural graph closure is useful investigation evidence, but it is not proof
that a vulnerable symbol can execute.  This module keeps that distinction in
one place so scoring, labels, correlations, and technique enrichment cannot
silently disagree.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum


class ReachabilityVerdict(StrEnum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNKNOWN = "unknown"
    UNLIKELY = "unlikely"


@dataclass(frozen=True, slots=True)
class ReachabilityAssessment:
    """A normalized verdict plus the evidence that produced it."""

    verdict: ReachabilityVerdict
    basis: tuple[str, ...]

    @property
    def permits_exploit_chain(self) -> bool:
        """Whether evidence is strong enough to assert an exploit chain."""

        return self.verdict in {ReachabilityVerdict.CONFIRMED, ReachabilityVerdict.LIKELY}


# Only function-level or runtime-observed evidence proves the vulnerable code
# executes; a graph path or package presence alone tops out at ``likely``.
CONFIRMING_BASIS = frozenset({"function_reachable", "runtime_observed"})


def review_only_match(tier: str | None) -> bool:
    return tier in {"unverified_range", "ambiguous_distro_release", "nvd_cpe_candidate"}


def assess_reachability(
    *,
    graph_reachable: bool | None = None,
    symbol_reachability: str | None = None,
    dependency_reachable: bool | None = None,
    direct_dependency: bool | None = False,
    affected_agents: bool = False,
    exposed_credentials: bool = False,
    exposed_tools: bool = False,
    declaration_only: bool = False,
    match_confidence_tier: str | None = None,
) -> ReachabilityAssessment:
    """Return one conservative verdict from all available evidence.

    Definitive negative graph or symbol evidence wins over exposure heuristics.
    Credentials and tools describe impact if exploitation occurs; they do not
    prove that the vulnerable code is executable.
    """

    if review_only_match(match_confidence_tier):
        return ReachabilityAssessment(ReachabilityVerdict.UNKNOWN, ("unverified_advisory_match",))

    symbol = (symbol_reachability or "").strip().lower()
    negative: list[str] = []
    if graph_reachable is False:
        negative.append("graph_unreachable")
    if symbol == "unreachable":
        negative.append("symbol_unreachable")
    if negative:
        return ReachabilityAssessment(ReachabilityVerdict.UNLIKELY, tuple(negative))

    if symbol == "function_reachable":
        proven = ("function_reachable", *(("graph_path",) if graph_reachable is True else ()))
        return ReachabilityAssessment(ReachabilityVerdict.CONFIRMED, proven)
    # A modeled graph path is structural: it shows the topology connects, not
    # that the vulnerable code executes.
    if graph_reachable is True:
        return ReachabilityAssessment(ReachabilityVerdict.LIKELY, ("graph_path",))

    if symbol == "unknown":
        return ReachabilityAssessment(ReachabilityVerdict.UNKNOWN, ("analysis_incomplete",))

    likely: list[str] = []
    if symbol == "package_reachable":
        likely.append("package_reachable")
    if dependency_reachable is True and not declaration_only:
        likely.append("dependency_path")
    if direct_dependency and affected_agents and not declaration_only:
        likely.append("direct_agent_dependency")
    if likely:
        return ReachabilityAssessment(ReachabilityVerdict.LIKELY, tuple(likely))

    if dependency_reachable is False and not declaration_only:
        return ReachabilityAssessment(ReachabilityVerdict.UNLIKELY, ("dependency_unreachable",))

    return _unknown_context(declaration_only, exposed_credentials, exposed_tools, direct_dependency)


def _unknown_context(
    declaration_only: bool, exposed_credentials: bool, exposed_tools: bool, direct_dependency: bool | None
) -> ReachabilityAssessment:
    context: list[str] = []
    if declaration_only:
        context.append("declaration_only")
    if exposed_credentials:
        context.append("credential_exposure")
    if exposed_tools:
        context.append("tool_exposure")
    if direct_dependency:
        context.append("direct_dependency")
    return ReachabilityAssessment(ReachabilityVerdict.UNKNOWN, tuple(context or ["insufficient_evidence"]))


def node_reachability(attributes: dict[str, object] | None) -> ReachabilityAssessment:
    """Normalize persisted vulnerability-node reachability attributes."""

    attrs = attributes or {}
    match_tier = str(attrs.get("match_confidence_tier") or "")
    if review_only_match(match_tier):
        return assess_reachability(match_confidence_tier=match_tier)
    explicit = str(attrs.get("reachability") or "").strip().lower()
    if explicit in {"confirmed", "likely", "unlikely"}:
        basis = attrs.get("reachability_basis")
        normalized_basis = tuple(str(item) for item in basis) if isinstance(basis, list) else ("persisted_verdict",)
        if explicit == "confirmed" and not CONFIRMING_BASIS.intersection(normalized_basis):
            return ReachabilityAssessment(ReachabilityVerdict.LIKELY, normalized_basis)
        return ReachabilityAssessment(ReachabilityVerdict(explicit), normalized_basis)
    graph_value = attrs.get("graph_reachable")
    dependency_value = attrs.get("dependency_reachable")
    return assess_reachability(
        graph_reachable=graph_value if isinstance(graph_value, bool) else None,
        symbol_reachability=str(attrs.get("symbol_reachability") or "") or None,
        dependency_reachable=dependency_value if isinstance(dependency_value, bool) else None,
    )


# Internal keys the findings projection stamps from the reaching attack paths.
GRAPH_PATH_VERDICT_KEY = "graph_path_reachability"
GRAPH_PATH_BASIS_KEY = "graph_path_reachability_basis"
_BUCKETS = {
    ReachabilityVerdict.CONFIRMED: "reachable",
    ReachabilityVerdict.LIKELY: "reachable",
    ReachabilityVerdict.UNLIKELY: "unreachable",
}


def _row_field(row: Mapping[str, object], evidence: Mapping[str, object], key: str) -> object:
    value = row.get(key)
    return value if value is not None else evidence.get(key)


def _optional_bool(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _exposed(row: Mapping[str, object], evidence: Mapping[str, object], listed_key: str, count_key: str) -> bool:
    counted = evidence.get(count_key)
    return bool(row.get(listed_key)) or (isinstance(counted, int) and not isinstance(counted, bool) and counted > 0)


def _persisted_verdict(value: object) -> ReachabilityAssessment | None:
    text = str(value or "").strip().lower()
    if text not in {item.value for item in ReachabilityVerdict}:
        return None
    # A bare persisted label carries no confirming basis.
    verdict = ReachabilityVerdict.LIKELY if text == ReachabilityVerdict.CONFIRMED else ReachabilityVerdict(text)
    return ReachabilityAssessment(verdict, ("persisted_verdict",))


def finding_reachability(row: Mapping[str, object]) -> ReachabilityAssessment | None:
    """The one verdict for a finding row, from the evidence stamped on it.

    Every finding surface (list, detail, filter, facets, MCP, exports) reads
    this. ``graph_reachable`` means any inbound path; a reaching path counts as
    ``graph_path`` evidence (``likely``) unless every reaching path is itself
    unverified. Only function-level or runtime-observed evidence confirms.
    Returns ``None`` for a row that was never assessed.
    """

    raw_evidence = row.get("evidence")
    evidence: Mapping[str, object] = raw_evidence if isinstance(raw_evidence, Mapping) else {}
    graph = _optional_bool(_row_field(row, evidence, "graph_reachable"))
    symbol = _row_field(row, evidence, "symbol_reachability")
    dependency = _optional_bool(_row_field(row, evidence, "dependency_reachable"))
    path_verdict = str(row.get(GRAPH_PATH_VERDICT_KEY) or "").strip().lower()
    if graph is None and not symbol and dependency is None and not path_verdict:
        return _persisted_verdict(row.get("reachability"))
    unverified_path = graph is True and path_verdict in {ReachabilityVerdict.UNKNOWN, ReachabilityVerdict.UNLIKELY}
    assessment = assess_reachability(
        graph_reachable=None if unverified_path else graph,
        symbol_reachability=str(symbol) if symbol else None,
        dependency_reachable=dependency,
        direct_dependency=_optional_bool(evidence.get("package_is_direct")),
        affected_agents=bool(row.get("affected_agents") or row.get("graph_reachable_from_agents")),
        exposed_credentials=_exposed(row, evidence, "exposed_credentials", "exposed_credential_count"),
        exposed_tools=_exposed(row, evidence, "exposed_tools", "exposed_tool_count"),
        declaration_only=evidence.get("package_reachability_evidence") == "declaration_only",
        match_confidence_tier=str(_row_field(row, evidence, "match_confidence_tier") or "") or None,
    )
    return _with_path_verdict(assessment, path_verdict, row.get(GRAPH_PATH_BASIS_KEY), unverified=unverified_path)


def _with_path_verdict(
    assessment: ReachabilityAssessment, path_verdict: str, raw_basis: object, *, unverified: bool
) -> ReachabilityAssessment:
    if unverified and assessment.verdict == ReachabilityVerdict.UNKNOWN:
        return ReachabilityAssessment(assessment.verdict, (*assessment.basis, "unverified_graph_path"))
    path_basis = tuple(str(item) for item in raw_basis) if isinstance(raw_basis, list | tuple) else ()
    confirming = tuple(item for item in path_basis if item in CONFIRMING_BASIS)
    if path_verdict == ReachabilityVerdict.CONFIRMED and confirming and assessment.verdict == ReachabilityVerdict.LIKELY:
        return ReachabilityAssessment(ReachabilityVerdict.CONFIRMED, (*confirming, *assessment.basis))
    return assessment


def reachability_bucket(row: Mapping[str, object]) -> str:
    """``reachable`` / ``unreachable`` / ``unassessed`` for the findings filter and facets."""

    assessment = finding_reachability(row)
    return _BUCKETS.get(assessment.verdict, "unassessed") if assessment is not None else "unassessed"


def stamp_finding_reachability(row: dict[str, object]) -> None:
    """Write the derived verdict onto a row; never-assessed rows are left alone."""

    assessment = finding_reachability(row)
    if assessment is not None:
        row["reachability"] = assessment.verdict.value
