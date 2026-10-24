"""IaC misconfiguration scanning — Dockerfile, Compose, Kubernetes, Terraform, CloudFormation, IAM, Helm, DCM, dbt.

Coordinator module that discovers and scans IaC files across all supported
formats.  Each scanner is regex/YAML-based with zero external dependencies.

Rules are aligned with cloud provider official documentation and best practices
(AWS Well-Architected, CIS Benchmarks) and mapped to applicable compliance
frameworks (NIST, CIS-AWS, SOC 2) where relevant.

Usage (legacy — returns findings list only)::

    from agent_bom.iac import scan_iac_directory
    findings = scan_iac_directory("/path/to/project")

Usage (context-aware — returns findings + per-scanner verdicts)::

    from agent_bom.iac import scan_iac_with_context
    from agent_bom.iac.models import ScanContext

    ctx = ScanContext(deployment_mode="native-app")
    result = scan_iac_with_context("/path/to/project", ctx)
    # result.findings  — same content as scan_iac_directory
    # result.verdicts  — per-scanner: ran / not-applicable / disabled
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

from agent_bom.iac.cloudformation import _is_cloudformation, scan_cloudformation
from agent_bom.iac.compose import is_compose_file, scan_compose
from agent_bom.iac.dbt_security import is_dbt_file, scan_dbt_file
from agent_bom.iac.dcm import is_dcm_migration, scan_dcm_migration
from agent_bom.iac.dockerfile import scan_dockerfile
from agent_bom.iac.github_actions_rules import is_workflow_file, scan_github_workflow
from agent_bom.iac.helm import scan_chart_yaml, scan_values_yaml
from agent_bom.iac.helm_templates import chart_root_for_template, scan_chart_templates
from agent_bom.iac.iam_policy import is_iam_policy_document, scan_iam_policy
from agent_bom.iac.kubernetes import scan_k8s_manifest
from agent_bom.iac.models import IaCFinding, ScanContext, ScannerVerdict, ScanResult, set_repository_context
from agent_bom.iac.suppressions import apply_inline_suppressions
from agent_bom.iac.terraform_security import scan_terraform_security
from agent_bom.traversal import iter_discovery_files

_DCM_AVAILABLE = True  # dcm.py is on main (#2222 merged)

__all__ = [
    "is_iac_file",
    "scan_iac_directory",
    "scan_iac_with_context",
    "scan_chart_yaml",
    "scan_values_yaml",
    "scan_dcm_migration",
    "scan_dbt_file",
    "scan_iam_policy",
    "ScanContext",
    "ScanResult",
    "ScannerVerdict",
]

# Canonical scanner IDs — order determines dispatch priority in the walk.
# Add new scanners here; the verdict table always has one entry per ID.
_SCANNER_IDS: tuple[str, ...] = (
    "helm",
    "github-actions",
    "compose",
    "dockerfile",
    "terraform",
    "dcm",
    "dbt",
    "kubernetes",
    "cloudformation",
    "iam-policy",
)

# Dockerfile filename patterns
_DOCKERFILE_NAMES = frozenset(
    {
        "Dockerfile",
        "dockerfile",
        "Dockerfile.dev",
        "Dockerfile.prod",
        "Dockerfile.ci",
        "Dockerfile.test",
    }
)

# K8s manifest filename suffixes + directory hints
_K8S_DIRS = frozenset({"k8s", "kubernetes", "deploy", "manifests", "helm"})

# Helm Chart.yaml names (case-insensitive)
_CHART_YAML_NAMES = frozenset({"Chart.yaml", "chart.yaml"})

# values.yaml / values-*.yaml pattern
_VALUES_YAML_RE = re.compile(r"^values(?:-[a-zA-Z0-9_-]+)?\.ya?ml$")


def _is_chart_yaml(path: Path) -> bool:
    return path.name in _CHART_YAML_NAMES


def _is_values_yaml(path: Path) -> bool:
    return bool(_VALUES_YAML_RE.match(path.name))


def _is_dockerfile(path: Path) -> bool:
    name = path.name
    if name in _DOCKERFILE_NAMES:
        return True
    if name.startswith("Dockerfile"):
        return True
    return False


def _is_k8s_manifest(path: Path) -> bool:
    if path.suffix not in (".yaml", ".yml"):
        return False
    for parent in path.parents:
        if parent.name.lower() in _K8S_DIRS:
            return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:2000]
        return "apiVersion:" in head and "kind:" in head
    except OSError:
        return False


def is_iac_file(path: Path, root: Path | None = None) -> bool:
    """True when :func:`scan_iac_with_context` would dispatch a scanner for ``path``.

    The single source of truth for "does this tree contain IaC?". Callers that
    auto-detect scan surfaces (the CLI ``--project`` expansion, the API repo
    tree scan) MUST use this rather than their own glob, or detection and
    dispatch drift apart — which is how ``scan`` came to report ``terraform``
    as a completed scan source while running zero IaC rules.

    ``root`` is only needed to recognise dbt project layouts; omit it for a
    cheap filename/marker check.
    """
    if _is_chart_yaml(path) or _is_values_yaml(path):
        return True
    if _is_dockerfile(path) or is_compose_file(path) or is_workflow_file(path):
        return True
    if path.suffix == ".tf":
        return True
    if is_dcm_migration(path):
        return True
    if root is not None and is_dbt_file(path, root):
        return True
    if _is_k8s_manifest(path):
        return True
    if is_iam_policy_document(path):
        return True
    return bool(_is_cloudformation(path))


def _scan_terraform(path: Path) -> list[IaCFinding]:
    from agent_bom.iac.terraform_ai import scan_terraform_ai

    return scan_terraform_security(path) + scan_terraform_ai(path)


def _scan_workflow(path: Path, root: Path, disabled: frozenset[str], files_matched: dict[str, int]) -> list[IaCFinding]:
    findings = [] if "github-actions" in disabled else scan_github_workflow(path)
    if "github-actions" not in disabled:
        files_matched["github-actions"] += 1
    # A dbt project's CI workflow is also a dbt input.
    if "dbt" not in disabled and is_dbt_file(path, root):
        files_matched["dbt"] += 1
        findings.extend(scan_dbt_file(path, root))
    return findings


# First match claims the file, in this order: DCM before dbt/K8s so a
# V<seq>__name.sql migration is never misclassified, and K8s before
# CloudFormation because apiVersion + kind is more specific than Resources:.
_DISPATCH: tuple[tuple[str, Callable[[Path, Path], bool], Callable[[Path, Path], list[IaCFinding]]], ...] = (
    (
        "helm",
        lambda p, _r: _is_chart_yaml(p) or _is_values_yaml(p),
        lambda p, _r: scan_chart_yaml(p) if _is_chart_yaml(p) else scan_values_yaml(p),
    ),
    ("compose", lambda p, _r: is_compose_file(p), lambda p, _r: scan_compose(p)),
    ("dockerfile", lambda p, _r: _is_dockerfile(p), lambda p, _r: scan_dockerfile(p)),
    ("terraform", lambda p, _r: p.suffix == ".tf", lambda p, _r: _scan_terraform(p)),
    ("dcm", lambda p, _r: is_dcm_migration(p), lambda p, _r: scan_dcm_migration(p)),
    ("dbt", is_dbt_file, scan_dbt_file),
    ("kubernetes", lambda p, _r: _is_k8s_manifest(p), lambda p, _r: scan_k8s_manifest(p)),
    ("cloudformation", lambda p, _r: bool(_is_cloudformation(p)), lambda p, _r: scan_cloudformation(p)),
    ("iam-policy", lambda p, _r: is_iam_policy_document(p), lambda p, _r: scan_iam_policy(p)),
)


def _dispatch_file(path: Path, root: Path, disabled: frozenset[str], files_matched: dict[str, int]) -> list[IaCFinding] | None:
    """Findings from the scanner that claims ``path``; ``None`` when no rule module does."""
    if is_workflow_file(path):
        return _scan_workflow(path, root, disabled, files_matched)
    for scanner_id, claims, scan in _DISPATCH:
        if not claims(path, root):
            continue
        if scanner_id in disabled:
            return []
        files_matched[scanner_id] += 1
        return scan(path, root)
    return None


def _build_verdicts(
    disabled: frozenset[str], files_matched: dict[str, int], verdict_reasons: dict[str, list[str]], ctx: ScanContext
) -> list[ScannerVerdict]:
    """One verdict per canonical scanner ID."""
    verdicts: list[ScannerVerdict] = []
    for sid in _SCANNER_IDS:
        if sid in disabled:
            verdicts.append(
                ScannerVerdict(
                    scanner_id=sid,
                    status="disabled",
                    files_scanned=0,
                    reason=f"locked out by deployment context ({ctx.deployment_mode})",
                )
            )
        elif files_matched.get(sid, 0) > 0:
            verdicts.append(
                ScannerVerdict(
                    scanner_id=sid,
                    status="ran",
                    files_scanned=files_matched[sid],
                    reason="; ".join(verdict_reasons.get(sid, [])),
                )
            )
        else:
            verdicts.append(
                ScannerVerdict(
                    scanner_id=sid,
                    status="not-applicable",
                    files_scanned=0,
                    reason="no matching files found in scan root",
                )
            )

    return verdicts


def scan_iac_with_context(
    root: str | Path,
    context: ScanContext | None = None,
) -> ScanResult:
    """Scan IaC files with per-scanner applicability and authorization verdicts.
    Each file has two gates:

    1. **Authorization** — ``context.enabled_scanners`` acts as an allowlist.
       ``None`` (default) means all scanners are unlocked.  A non-empty
       frozenset locks out any scanner whose ID is absent; those scanners
       emit a ``"disabled"`` verdict and are never dispatched.

    2. **Applicability** — tracked by counting files matched per scanner during
       the single directory walk.  Zero matches → ``"not-applicable"``; one or
       more → ``"ran"``.  This is the expected status for scanners whose file
       types don't exist in the scanned tree (e.g. Dockerfile scanner on a
       pure-Terraform repo, or any bare-metal scanner inside a Snowflake Native
       App deployment where there are simply no host-level files to inspect).

    Parameters
    ----------
    root:
        Root directory to scan recursively.
    context:
        Optional deployment and authorization context.  Defaults to
        ``ScanContext(deployment_mode="standalone")`` with all scanners
        unlocked.

    Returns
    -------
    ScanResult
        ``findings`` is identical in content to ``scan_iac_directory``.
        ``verdicts`` has one ``ScannerVerdict`` per known scanner ID.
    """
    ctx = context or ScanContext()
    root_path = Path(root).expanduser().resolve()

    # A single explicit file (e.g. `agent-bom iac Dockerfile`) scans just that
    # file; a directory walks recursively. Only a genuinely missing path is a
    # hard no-op — silently returning zero findings for an existing file the
    # operator named is a false-negative in CI gates.
    explicit_file = root_path.is_file()
    if not root_path.exists():
        early_verdicts: list[ScannerVerdict] = [
            ScannerVerdict(
                scanner_id=sid,
                status="disabled" if (ctx.enabled_scanners is not None and sid not in ctx.enabled_scanners) else "not-applicable",
                files_scanned=0,
                reason="scan root does not exist",
            )
            for sid in _SCANNER_IDS
        ]
        return ScanResult(findings=[], verdicts=early_verdicts)

    # Gate 1: build the disabled set up-front so the walk loop is O(1) per file.
    if ctx.enabled_scanners is not None:
        disabled: frozenset[str] = frozenset(sid for sid in _SCANNER_IDS if sid not in ctx.enabled_scanners)
    else:
        disabled = frozenset()

    findings: list[IaCFinding] = []
    not_evaluated: list[str] = []
    chart_roots: set[Path] = set()
    verdict_reasons: dict[str, list[str]] = defaultdict(list)
    files_matched: dict[str, int] = defaultdict(int)
    from agent_bom.core.severity import severity_worst_first_rank

    walk_root = root_path.parent if explicit_file else root_path
    walk_paths = [root_path] if explicit_file else sorted(iter_discovery_files(root_path))
    for path in walk_paths:
        if not path.is_file():
            continue
        # An explicitly named file is always scanned; the dotfile/vendored-dir
        # filters below only apply when walking a directory tree.
        if not explicit_file:
            relative_parts = path.relative_to(walk_root).parts
            if any(part.startswith(".") for part in relative_parts) and not (".github" in relative_parts and "workflows" in relative_parts):
                continue
            if "node_modules" in path.parts or "__pycache__" in path.parts:
                continue

        first_finding = len(findings)
        chart_root = chart_root_for_template(path)
        if chart_root is not None:
            # Templates are evaluated per chart after the walk (rendered or textual).
            if "helm" not in disabled:
                chart_roots.add(chart_root)
            continue
        dispatched = _dispatch_file(path, root_path, disabled, files_matched)
        if dispatched is None and explicit_file:
            not_evaluated.append(path.name)
        findings.extend(dispatched or [])

        set_repository_context(findings[first_finding:], path.relative_to(walk_root).as_posix())

    # A subchart under charts/ is rendered as part of its parent chart.
    for chart_root in sorted(r for r in chart_roots if not any(other in r.parents for other in chart_roots)):
        chart = scan_chart_templates(chart_root, walk_root)
        files_matched["helm"] += chart.files
        findings.extend(chart.findings)
        if chart.reason:
            verdict_reasons["helm"].append(chart.reason)

    # Enrich with MITRE ATT&CK and MITRE ATLAS technique IDs
    from agent_bom.iac.atlas_mapping import get_atlas_techniques
    from agent_bom.iac.attack_mapping import get_attack_techniques

    for finding in findings:
        if not finding.attack_techniques:
            finding.attack_techniques = get_attack_techniques(finding.rule_id)
        if not finding.atlas_techniques:
            finding.atlas_techniques = get_atlas_techniques(finding.rule_id, message=finding.message)

    findings, suppressed = apply_inline_suppressions(findings, walk_root)
    findings.sort(key=lambda f: (severity_worst_first_rank(f.severity), f.file_path, f.line_number))

    verdicts = _build_verdicts(disabled, files_matched, verdict_reasons, ctx)
    return ScanResult(findings=findings, verdicts=verdicts, not_evaluated=not_evaluated, suppressed=suppressed)


def scan_iac_directory(root: str | Path) -> list[IaCFinding]:
    """Scan a directory tree for IaC misconfigurations across all supported formats.

    Legacy entry point — returns findings list only.  New callers should
    prefer ``scan_iac_with_context`` which also returns per-scanner verdicts.

    Parameters
    ----------
    root:
        Root directory to scan recursively.

    Returns
    -------
    list[IaCFinding]
        All findings from all scanners, sorted by severity then file path.
    """
    return scan_iac_with_context(root).findings
