"""Data models for IaC misconfiguration findings."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from typing import Any


class IaCResourceType(str, Enum):
    """First-class IaC resource types surfaced by agent-bom scanners."""

    # Terraform
    TF_RESOURCE = "tf_resource"
    # Kubernetes
    K8S_POD = "k8s_pod"
    K8S_DEPLOYMENT = "k8s_deployment"
    K8S_SERVICE = "k8s_service"
    K8S_ROLE = "k8s_role"
    K8S_CLUSTER_ROLE = "k8s_cluster_role"
    K8S_NETWORK_POLICY = "k8s_network_policy"
    # Dockerfile
    DOCKERFILE = "dockerfile"
    # CloudFormation
    CFN_RESOURCE = "cfn_resource"
    # Standalone AWS IAM policy / trust policy
    IAM_POLICY = "iam_policy"
    # Helm
    HELM_RESOURCE = "helm_resource"
    # Snowflake DCM (Database Change Management)
    DCM_ROLE = "dcm_role"
    DCM_NETWORK_POLICY = "dcm_network_policy"
    DCM_TABLE = "dcm_table"
    DCM_GRANT = "dcm_grant"
    DCM_TASK = "dcm_task"
    DCM_SERVICE = "dcm_service"
    # dbt
    DBT_PROJECT = "dbt_project"


@dataclass(frozen=True)
class IaCResourceRef:
    """Identity of the declared resource a finding is about, where the parser knows it."""

    kind: str
    name: str
    namespace: str = ""
    labels: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "name": self.name, "namespace": self.namespace, "labels": dict(self.labels)}


@dataclass
class IaCFinding:
    """A single IaC misconfiguration finding."""

    rule_id: str  # e.g. "DOCKER-001", "K8S-001", "TF-SEC-001"
    severity: str  # critical, high, medium, low
    title: str  # Short description
    message: str  # Detailed explanation with fix guidance
    file_path: str  # Relative path to the file
    line_number: int  # Line where the issue was found
    category: str  # "dockerfile", "kubernetes", "terraform", "dcm"
    compliance: list[str] = field(default_factory=list)  # e.g. ["CIS-5.1", "NIST-CM-6"]
    attack_techniques: list[str] = field(default_factory=list)  # MITRE ATT&CK IDs, e.g. ["T1552.001"]
    atlas_techniques: list[str] = field(default_factory=list)  # MITRE ATLAS IDs, e.g. ["AML.T0010"]
    remediation: str = ""  # Fix guidance
    resource_type: IaCResourceType | None = None  # Structured resource type for graph/compliance wiring
    repository_relative_path: str | None = None  # Set only by a scanner with a known repository root
    resource: IaCResourceRef | None = None  # Declared resource identity (Kubernetes kind/name/namespace/labels)
    suppression: dict[str, Any] | None = None  # Accepted-exception record; set only on suppressed findings


@dataclass
class ScanContext:
    """Deployment and authorization context for an IaC scan.

    Controls which scanners are authorised to run (``enabled_scanners``) and
    records the deployment mode so callers can adapt output accordingly.

    Two orthogonal gates are applied in ``scan_iac_with_context`` for each
    scanner:

    1. **Authorization** — is the scanner in ``enabled_scanners``?
       ``None`` means all scanners are unlocked (default).
       A non-empty frozenset is an explicit allowlist; scanners absent from it
       are locked out and emit a ``"disabled"`` verdict.

    2. **Applicability** — did the scanner match any files during the walk?
       Zero files matched → ``"not-applicable"``; one or more → ``"ran"``.

    Deployment modes
    ----------------
    ``"standalone"``
        Full agent-bom install (bare-metal, Docker, Kubernetes, CI/CD).
        All scanners unlocked by default.
    ``"native-app"``
        Running inside a Snowflake Native App (SPCS).
        Bare-metal / OS-level scanners will emit ``not-applicable`` naturally
        because there are no matching files; no special handling required.
    ``"github-action"``
        Running as the agent-bom GitHub Action.
        Same scanner set as standalone; context surfaces in SARIF output.
    ``"mcp"``
        Invoked via the MCP tool interface.
        Context is passed by the MCP client in tool arguments.
    """

    deployment_mode: str = "standalone"
    enabled_scanners: frozenset[str] | None = None  # None = all unlocked
    # Accepted exceptions from an ignore file or the tenant store; inline markers are read from the files.
    exceptions: tuple[Any, ...] = ()  # agent_bom.core.iac_exceptions.IaCException
    # IaC rules of a policy-as-code file (allow / warn / block).
    policy: Any = None  # agent_bom.iac.policy.IaCPolicy
    # Date exceptions are evaluated against; ``None`` means today (UTC).
    today: date | None = None


@dataclass
class ScannerVerdict:
    """Capability verdict for a single scanner after a scan run.

    Statuses
    --------
    ``"ran"``
        Scanner was authorised, found at least one target file, and executed.
    ``"not-applicable"``
        Scanner was authorised but found zero matching files in the scan root.
        This is the expected status for scanners whose file types don't exist
        in the scanned directory (e.g. Dockerfile scanner on a pure-Terraform
        repo, or bare-metal scanners inside a Snowflake Native App).
    ``"disabled"``
        Scanner was explicitly locked out via ``ScanContext.enabled_scanners``.
        No files were inspected.
    """

    scanner_id: str
    status: str  # "ran" | "not-applicable" | "disabled"
    files_scanned: int = 0
    reason: str = ""  # human-readable; populated for not-applicable + disabled


@dataclass
class ScanResult:
    """Complete result of a context-aware IaC scan.

    ``findings`` is identical in content to the list returned by the legacy
    ``scan_iac_directory`` function.  ``verdicts`` is the per-scanner
    capability table — one entry per known scanner regardless of whether it
    ran, giving callers a transparent record of what was and was not checked.
    """

    findings: list[IaCFinding] = field(default_factory=list)
    verdicts: list[ScannerVerdict] = field(default_factory=list)
    # Findings an accepted exception covers; each carries its ``suppression`` record.
    suppressed: list[IaCFinding] = field(default_factory=list)
    # Expired, soon-to-expire, invalid or policy-rejected exceptions worth telling the operator about.
    notices: list[Any] = field(default_factory=list)  # agent_bom.core.iac_exceptions.ExceptionNotice
    # IaC policy-as-code outcome (``None`` when no policy has IaC rules).
    policy_result: dict[str, Any] | None = None
    # Explicitly named files that no rule module evaluates. Zero findings for
    # them means "not evaluated", never "clean".
    not_evaluated: list[str] = field(default_factory=list)

    @property
    def evaluated(self) -> bool:
        """True when at least one scanner ran over at least one file."""
        return any(v.status == "ran" for v in self.verdicts)


def set_repository_context(findings: list[IaCFinding], relative_path: str) -> None:
    """Attach the path supplied by dispatch with a known scan root."""
    for finding in findings:
        finding.repository_relative_path = relative_path
        finding.file_path = relative_path


# ── serialized shape (``iac_findings`` in JSON exports) ──────────────────────
# ``findings`` holds active findings: gates, policy and the unified finding stream read
# only these. ``suppressed`` keeps every finding an accepted exception covers, with its
# suppression record. ``exceptions`` counts what was accepted, expired or is about to.


def iac_finding_row(finding: IaCFinding) -> dict[str, Any]:
    row: dict[str, Any] = {
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "title": finding.title,
        "message": finding.message,
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "category": finding.category,
        "compliance": finding.compliance,
        "attack_techniques": finding.attack_techniques,
        "remediation": finding.remediation,
    }
    if finding.resource is not None:
        row["resource"] = finding.resource.to_dict()
    if finding.suppression is not None:
        row["suppressed"] = True
        row["suppression"] = dict(finding.suppression)
    return row


def exception_summary(suppressed: Iterable[IaCFinding], notices: Iterable[Any]) -> dict[str, Any]:
    records = [f.suppression for f in suppressed if f.suppression is not None]
    notice_list = list(notices)
    return {
        "accepted": len(records),
        "expired": sum(1 for n in notice_list if n.kind == "expired"),
        "expiring_soon": sum(1 for n in notice_list if n.kind == "expiring"),
        "invalid": sum(1 for n in notice_list if n.kind == "invalid"),
        "rejected": sum(1 for n in notice_list if n.kind == "rejected"),
        "by_source": dict(sorted(Counter(str(r.get("source")) for r in records).items())),
        "notices": [n.to_dict() for n in notice_list],
    }


def iac_findings_payload(
    findings: Iterable[IaCFinding],
    suppressed: Iterable[IaCFinding] = (),
    notices: Iterable[Any] = (),
    *,
    policy: dict[str, Any] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    active = list(findings)
    accepted = list(suppressed)
    payload: dict[str, Any] = {
        **extra,
        "total": len(active),
        "findings": [iac_finding_row(f) for f in active],
        "suppressed": [iac_finding_row(f) for f in accepted],
        "exceptions": exception_summary(accepted, notices),
    }
    if policy is not None:
        payload["policy"] = policy
    return payload


def merge_policy_results(results: Iterable[dict[str, Any] | None]) -> dict[str, Any] | None:
    """Combine per-path IaC policy outcomes into one."""
    present = [r for r in results if r]
    if not present:
        return None
    merged: dict[str, Any] = {"policy_name": present[0].get("policy_name"), "violations": [], "failures": [], "warnings": [], "allowed": []}
    for result in present:
        for key in ("violations", "failures", "warnings", "allowed"):
            merged[key].extend(result.get(key) or [])
    merged["passed"] = not merged["failures"]
    return merged
