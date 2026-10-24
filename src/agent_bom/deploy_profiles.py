"""Canonical Helm chart profiles for shipped deployment examples."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class HelmValidationProfile:
    """A named Helm profile backed by shipped chart examples."""

    name: str
    description: str
    values_files: tuple[Path, ...] = field(default_factory=tuple)
    set_arguments: tuple[str, ...] = field(default_factory=tuple)
    set_file_arguments: tuple[tuple[str, Path], ...] = field(default_factory=tuple)
    # Literal text the render must contain, so an overlay that silently stops
    # applying fails validation instead of rendering its base unchanged.
    expect_rendered: tuple[str, ...] = field(default_factory=tuple)


def helm_chart_dir(repo_root: Path) -> Path:
    return repo_root / "deploy" / "helm" / "agent-bom"


def helm_example_dir(repo_root: Path) -> Path:
    return helm_chart_dir(repo_root) / "examples"


def ingress_hosts_missing_paths(rendered: str) -> list[str]:
    """Return ``host`` values whose rendered Ingress rule carries no HTTP paths.

    A rule that renders ``http.paths`` as ``null``/empty is an invalid Ingress: it
    binds a hostname but routes nowhere. This guards against example values files
    that override ``ingress.hosts`` without carrying ``apiPaths``/``uiPaths`` — a
    render that exits 0 yet produces an ingress that cannot route traffic.
    """

    offenders: list[str] = []
    for document in rendered.split("\n---"):
        if "kind: Ingress" not in document:
            continue

        manifest = None
        try:
            import yaml

            manifest = yaml.safe_load(document)
        except Exception:
            manifest = None

        if isinstance(manifest, dict):
            rules = (manifest.get("spec") or {}).get("rules") or []
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                paths = ((rule.get("http") or {}).get("paths")) or []
                if not paths:
                    offenders.append(str(rule.get("host", "<no-host>")))
            continue

        # Fallback text scan when PyYAML is unavailable (bare CI python): every
        # rendered ``paths:`` line must be immediately followed by a ``- path:``
        # list item, otherwise the rule routes nowhere.
        lines = document.splitlines()
        current_host = "<no-host>"
        for index, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("host:"):
                current_host = stripped.split("host:", 1)[1].strip().strip('"')
            if stripped == "paths:":
                following = next(
                    (nxt.strip() for nxt in lines[index + 1 :] if nxt.strip()),
                    "",
                )
                if not following.startswith("- path:"):
                    offenders.append(current_host)
    return offenders


def _pilot_helm_profiles(examples: Path) -> list[HelmValidationProfile]:
    """Scanner-only and focused pilot profiles."""

    return [
        HelmValidationProfile(
            name="scanner-only",
            description="Default scanner-only render (controlPlane.enabled=false).",
        ),
        HelmValidationProfile(
            name="sqlite-pilot",
            description="Single-node SQLite demo control plane for fast packaged pilots.",
            values_files=(examples / "eks-control-plane-sqlite-pilot-values.yaml",),
        ),
        HelmValidationProfile(
            name="synthetic-enterprise-story",
            description="Single-node dashboard seeded only with the fictional cross-vendor enterprise story.",
            values_files=(examples / "synthetic-enterprise-story-values.yaml",),
        ),
        HelmValidationProfile(
            name="focused-pilot",
            description="Focused EKS pilot with control plane, scanner, and narrowed ingress.",
            values_files=(examples / "eks-mcp-pilot-values.yaml",),
        ),
        HelmValidationProfile(
            name="enterprise-demo",
            description="Focused EKS pilot with scheduled AWS estate inventory via IRSA.",
            values_files=(
                examples / "eks-mcp-pilot-values.yaml",
                examples / "eks-enterprise-demo-overlay.yaml",
            ),
        ),
        HelmValidationProfile(
            name="focused-pilot-byo-postgres",
            description="Focused EKS pilot plus operator-owned Postgres-compatible control-plane database.",
            values_files=(
                examples / "eks-mcp-pilot-values.yaml",
                examples / "byo-postgres-values.yaml",
            ),
        ),
    ]


def _production_helm_profiles(examples: Path) -> list[HelmValidationProfile]:
    """Production control-plane profiles and their hardening overlays."""

    return [
        HelmValidationProfile(
            name="production-secret-sync",
            description="ExternalSecrets-only bootstrap stage for the production EKS profile.",
            values_files=(
                examples / "eks-production-values.yaml",
                examples / "eks-production-secret-sync-values.yaml",
            ),
        ),
        HelmValidationProfile(
            name="production",
            description="Postgres-backed production EKS defaults with autoscaling and backups.",
            values_files=(examples / "eks-production-values.yaml",),
        ),
        HelmValidationProfile(
            name="keda-autoscaling",
            description="Production EKS defaults with KEDA-backed control-plane API autoscaling.",
            values_files=(
                examples / "eks-production-values.yaml",
                examples / "eks-keda-values.yaml",
            ),
        ),
        HelmValidationProfile(
            name="eks-vanilla",
            description="Production EKS profile using ALB, IRSA, Kubernetes Secrets, and RDS/Postgres.",
            values_files=(examples / "eks-vanilla-values.yaml",),
        ),
        HelmValidationProfile(
            name="mesh-hardening",
            description="Istio and Kyverno hardening overlay for operator-managed clusters.",
            values_files=(examples / "eks-istio-kyverno-values.yaml",),
        ),
        HelmValidationProfile(
            name="snowflake-backend",
            description="Warehouse export/backend overlay for Snowflake-integrated deployments.",
            values_files=(examples / "eks-snowflake-values.yaml",),
        ),
        HelmValidationProfile(
            name="gateway-runtime",
            description="Focused pilot plus single-writer PVC-backed gateway with shipped upstream example.",
            values_files=(examples / "eks-mcp-pilot-values.yaml",),
            set_arguments=(
                "gateway.enabled=true",
                "gateway.replicas=1",
                "gateway.persistence.enabled=true",
                "gateway.persistence.existingClaim=agent-bom-gateway-audit",
            ),
            set_file_arguments=(("gateway.upstreamsYaml", examples / "gateway-upstreams.example.yaml"),),
        ),
        HelmValidationProfile(
            name="airgap-vuln-db",
            description="Disconnected control plane with a Secret-mounted vulns.db and no egress.",
            values_files=(examples / "airgap-vuln-db-values.yaml",),
        ),
    ]


def _collector_and_identity_helm_profiles(examples: Path) -> list[HelmValidationProfile]:
    """Collector identity, mTLS and OIDC overlays rendered on their base profile."""

    return [
        HelmValidationProfile(
            name="aks-collector-workload-identity",
            description="Scanner-only AKS collector using Azure Workload Identity.",
            values_files=(examples / "aks-collector-workload-identity-values.yaml",),
            expect_rendered=("azure.workload.identity/client-id",),
        ),
        HelmValidationProfile(
            name="eks-collector-irsa",
            description="Scanner-only EKS collector using IRSA.",
            values_files=(examples / "eks-collector-irsa-values.yaml",),
            expect_rendered=("eks.amazonaws.com/role-arn",),
        ),
        HelmValidationProfile(
            name="gke-collector-workload-identity",
            description="Scanner-only GKE collector using Workload Identity.",
            values_files=(examples / "gke-collector-workload-identity-values.yaml",),
            expect_rendered=("iam.gke.io/gcp-service-account",),
        ),
        HelmValidationProfile(
            name="multicloud-collector",
            description="Scanner-only collector reaching AWS, GCP, Azure and Snowflake.",
            values_files=(examples / "multicloud-collector-values.yaml",),
            expect_rendered=("AGENT_BOM_GCP_IMPERSONATE_SA",),
        ),
        HelmValidationProfile(
            name="collector-mtls",
            description="Production mesh-hardened control plane plus the collector mTLS overlay.",
            values_files=(
                examples / "eks-production-values.yaml",
                examples / "eks-istio-kyverno-values.yaml",
                examples / "collector-mtls-values.yaml",
            ),
            expect_rendered=("agent-bom-collector-client-tls",),
        ),
        HelmValidationProfile(
            name="control-plane-identity",
            description="Production control plane plus the keyless control-plane identity overlay.",
            values_files=(
                examples / "eks-production-values.yaml",
                examples / "control-plane-identity-values.yaml",
            ),
            expect_rendered=("arn:aws:iam::123456789012:role/agent-bom-scanner",),
        ),
        HelmValidationProfile(
            name="oidc-secret-file",
            description="Focused pilot plus a confidential OIDC client secret mounted from a file.",
            values_files=(
                examples / "eks-mcp-pilot-values.yaml",
                examples / "oidc-secret-file-values.yaml",
            ),
            expect_rendered=("AGENT_BOM_OIDC_CLIENT_SECRET_FILE",),
        ),
        HelmValidationProfile(
            name="oidc-discovery-shim",
            description="Focused pilot gateway plus the OIDC discovery shim overlay.",
            values_files=(
                examples / "eks-mcp-pilot-values.yaml",
                examples / "oidc-discovery-shim-values.yaml",
            ),
            set_file_arguments=(("gateway.upstreamsYaml", examples / "gateway-upstreams.example.yaml"),),
            expect_rendered=("AGENT_BOM_OIDC_DISCOVERY_SHIM_JSON", "name: jira"),
        ),
    ]


def helm_validation_profiles(repo_root: Path) -> list[HelmValidationProfile]:
    """Return the canonical shipped Helm profile matrix."""

    examples = helm_example_dir(repo_root)
    return [
        *_pilot_helm_profiles(examples),
        *_production_helm_profiles(examples),
        *_collector_and_identity_helm_profiles(examples),
    ]


def build_helm_profile_command(
    repo_root: Path,
    profile_name: str,
    *,
    release_name: str = "agent-bom",
    namespace: str = "agent-bom",
    create_namespace: bool = True,
    extra_values_files: tuple[Path, ...] = (),
    extra_set_arguments: tuple[str, ...] = (),
    extra_set_file_arguments: tuple[tuple[str, Path], ...] = (),
) -> list[str]:
    """Build the canonical Helm upgrade/install command for a shipped profile."""

    profiles = {profile.name: profile for profile in helm_validation_profiles(repo_root)}
    try:
        profile = profiles[profile_name]
    except KeyError as exc:
        available = ", ".join(sorted(profiles))
        raise KeyError(f"unknown Helm profile '{profile_name}' (available: {available})") from exc

    # The production secret bootstrap must remain a separate Helm release from
    # the workloads. Reusing the normal ``agent-bom`` release would make the
    # subsequent production upgrade delete the ExternalSecret objects (and,
    # with creationPolicy=Owner, their generated target Secrets). Keep the
    # common CLI/wrapper default safe while still allowing an explicitly named
    # separate secret release for multi-install environments.
    if profile_name == "production-secret-sync" and release_name == "agent-bom":
        release_name = "agent-bom-secrets"

    cmd = [
        "helm",
        "upgrade",
        "--install",
        release_name,
        str(helm_chart_dir(repo_root)),
        "--namespace",
        namespace,
    ]
    if create_namespace:
        cmd.append("--create-namespace")

    for values_file in (*profile.values_files, *extra_values_files):
        cmd.extend(["-f", str(values_file)])
    for set_argument in (*profile.set_arguments, *extra_set_arguments):
        cmd.extend(["--set", set_argument])
    for key, path in (*profile.set_file_arguments, *extra_set_file_arguments):
        cmd.extend(["--set-file", f"{key}={path}"])
    return cmd
