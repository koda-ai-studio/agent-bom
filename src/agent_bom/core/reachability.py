"""Canonical reachability truth used across findings and attack paths.

Structural graph closure is useful investigation evidence, but it is not proof
that a vulnerable symbol can execute.  This module keeps that distinction in
one place so scoring, labels, correlations, and technique enrichment cannot
silently disagree.
"""

from __future__ import annotations

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


def _review_only_match(tier: str | None) -> bool:
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

    if _review_only_match(match_confidence_tier):
        return ReachabilityAssessment(ReachabilityVerdict.UNKNOWN, ("unverified_advisory_match",))

    symbol = (symbol_reachability or "").strip().lower()
    negative: list[str] = []
    if graph_reachable is False:
        negative.append("graph_unreachable")
    if symbol == "unreachable":
        negative.append("symbol_unreachable")
    if negative:
        return ReachabilityAssessment(ReachabilityVerdict.UNLIKELY, tuple(negative))

    positive: list[str] = []
    if graph_reachable is True:
        positive.append("graph_path")
    if symbol == "function_reachable":
        positive.append("function_reachable")
    if positive:
        return ReachabilityAssessment(ReachabilityVerdict.CONFIRMED, tuple(positive))

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
    if _review_only_match(match_tier):
        return assess_reachability(match_confidence_tier=match_tier)
    explicit = str(attrs.get("reachability") or "").strip().lower()
    if explicit in {"confirmed", "likely", "unlikely"}:
        basis = attrs.get("reachability_basis")
        normalized_basis = tuple(str(item) for item in basis) if isinstance(basis, list) else ("persisted_verdict",)
        return ReachabilityAssessment(ReachabilityVerdict(explicit), normalized_basis)
    graph_value = attrs.get("graph_reachable")
    dependency_value = attrs.get("dependency_reachable")
    return assess_reachability(
        graph_reachable=graph_value if isinstance(graph_value, bool) else None,
        symbol_reachability=str(attrs.get("symbol_reachability") or "") or None,
        dependency_reachable=dependency_value if isinstance(dependency_value, bool) else None,
    )
