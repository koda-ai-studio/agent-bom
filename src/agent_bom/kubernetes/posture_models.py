"""Live Kubernetes posture result and collector-evidence models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from agent_bom.cloud.benchmark_provenance import BenchmarkProvenance, kubernetes_benchmark_provenance
from agent_bom.iac.models import IaCFinding

if TYPE_CHECKING:
    from agent_bom.evidence.scan_run import ScanRun


class CollectorState(str, Enum):
    """Execution state for one live Kubernetes evidence collector."""

    EXECUTED = "executed"
    SKIPPED = "skipped"
    UNEVALUABLE = "unevaluable"
    FAILED = "failed"


class K8sPostureStatus(str, Enum):
    """Aggregate completeness of a live Kubernetes posture run."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True)
class K8sCollectorEvidence:
    """Auditable execution evidence for one read-only collector."""

    collector_id: str
    state: CollectorState
    object_count: int = 0
    pages: int = 0
    truncated: bool = False
    message: str = ""
    transport: str = ""


@dataclass
class K8sPostureResult:
    """Findings plus explicit collection completeness for a posture run."""

    findings: list[IaCFinding] = field(default_factory=list)
    collectors: list[K8sCollectorEvidence] = field(default_factory=list)
    status: K8sPostureStatus = K8sPostureStatus.FAILED
    transport: str = ""
    benchmark: BenchmarkProvenance = field(default_factory=kubernetes_benchmark_provenance)

    def severity_summary(self) -> dict[str, int]:
        """Return the finding count per severity bucket (one source of truth).

        Shared verbatim by the REST route and the MCP tool so the API, MCP, and
        CLI evidence dict reconcile 1:1 on the same numbers.
        """
        summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            bucket = str(getattr(finding, "severity", "") or "").strip().lower()
            if bucket in summary:
                summary[bucket] += 1
        return summary

    def to_scan_run(self) -> "ScanRun":
        """Project collection completeness onto the canonical ``ScanRun`` contract.

        The aggregate posture status maps to the execution outcome
        (COMPLETE/PARTIAL/FAILED) and every collector that could not be fully
        evaluated emits one coverage-affecting :class:`ScanIssue`:

        * ``UNEVALUABLE`` (a denied/absent read, e.g. 403) → a ``warning``
          coded ``k8s_collector_unevaluable``;
        * ``FAILED`` (a transport/read error) → an ``error`` coded
          ``k8s_collector_failed``;
        * a ``truncated`` read that hit its configured bound → a ``warning``
          coded ``k8s_collector_truncated``.

        Because each issue sets ``affects_coverage=True``, a run that would
        otherwise read COMPLETE is derived down to PARTIAL by ``ScanRun`` — a
        denied or partial collector can never surface as a clean pass.
        ``SKIPPED`` (opt-in, deliberately not run) is not a coverage gap and
        emits no issue.
        """
        from agent_bom.evidence.scan_run import ScanIssue, ScanOutcome, ScanRun

        outcome = {
            K8sPostureStatus.COMPLETE: ScanOutcome.COMPLETE,
            K8sPostureStatus.PARTIAL: ScanOutcome.PARTIAL,
            K8sPostureStatus.FAILED: ScanOutcome.FAILED,
        }[self.status]

        issues: list[ScanIssue] = []
        for collector in self.collectors:
            if collector.state is CollectorState.FAILED:
                issues.append(
                    ScanIssue(
                        code="k8s_collector_failed",
                        stage="kubernetes-posture",
                        source=collector.collector_id,
                        message=collector.message or "collector failed",
                        severity="error",
                        affects_coverage=True,
                    )
                )
            elif collector.state is CollectorState.UNEVALUABLE:
                issues.append(
                    ScanIssue(
                        code="k8s_collector_unevaluable",
                        stage="kubernetes-posture",
                        source=collector.collector_id,
                        message=collector.message or "collector could not be evaluated",
                        severity="warning",
                        affects_coverage=True,
                    )
                )
            elif collector.state is CollectorState.EXECUTED and collector.truncated:
                issues.append(
                    ScanIssue(
                        code="k8s_collector_truncated",
                        stage="kubernetes-posture",
                        source=collector.collector_id,
                        message=collector.message or "collection reached its configured bound",
                        severity="warning",
                        affects_coverage=True,
                    )
                )

        return ScanRun(outcome=outcome, issues=issues)

    def to_evidence_dict(self) -> dict[str, Any]:
        """Render the machine-readable posture evidence envelope.

        Carries the pinned benchmark provenance alongside every collector's
        explicit execution state so a denied/partial/timeout read is visible as
        ``unevaluable``/``failed`` and can never be read as a clean ``PASS``.
        """
        return {
            "status": self.status.value,
            "transport": self.transport,
            "finding_count": len(self.findings),
            "benchmark": self.benchmark.to_dict(),
            "collectors": [
                {
                    "collector_id": collector.collector_id,
                    "state": collector.state.value,
                    "object_count": collector.object_count,
                    "pages": collector.pages,
                    "truncated": collector.truncated,
                    "message": collector.message,
                    "transport": collector.transport,
                }
                for collector in self.collectors
            ],
        }
