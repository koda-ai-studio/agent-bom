"""Guards for evaluating with the control plane's *own* cloud identity.

Most cloud work runs against a tenant's stored, scoped connection. A few
surfaces instead evaluate with whatever ambient credentials the process itself
holds — an instance role, an assumed role, a mounted profile. That is a
different trust level, so it is off unless an operator turns it on, and the
caller never chooses which credential gets spent.

The guard lives here rather than in a route because REST and the MCP tool call
the same benchmark. Gating only one of them would leave the other as an open
path to the same credentials.
"""

from __future__ import annotations

from agent_bom.core.settings import env_raw

AMBIENT_CIS_ENV = "AGENT_BOM_CLOUD_CIS_BENCHMARK"
AMBIENT_SNOWFLAKE_GOVERNANCE_ENV = "AGENT_BOM_SNOWFLAKE_GOVERNANCE"
AWS_PROFILE_ENV = "AGENT_BOM_AWS_PROFILE"
API_K8S_SCANS_ENV = "AGENT_BOM_API_K8S_SCANS"
API_K8S_CONTEXTS_ENV = "AGENT_BOM_API_K8S_CONTEXTS"
API_CONNECTOR_SCANS_ENV = "AGENT_BOM_API_CONNECTOR_SCANS"
API_MODEL_HUB_CREDENTIALS_ENV = "AGENT_BOM_API_MODEL_HUB_CREDENTIALS"
AMBIENT_TENANT_ENV = "AGENT_BOM_AMBIENT_CREDENTIALS_TENANT"

_TRUTHY = frozenset({"1", "true", "yes", "on"})

DISABLED_NOTE = (
    "Ambient-credential CIS benchmark is opt-in. Set AGENT_BOM_CLOUD_CIS_BENCHMARK=1 to allow this control "
    "plane to evaluate its own cloud identity. Prefer scanning through a tenant cloud connection instead."
)

SNOWFLAKE_GOVERNANCE_DISABLED_NOTE = (
    "Snowflake governance and Cortex reads use this control plane's own Snowflake credentials and are opt-in. "
    "Set AGENT_BOM_SNOWFLAKE_GOVERNANCE=1 on the API to let admins read them."
)

PROFILE_REJECTED_NOTE = (
    "The profile parameter is not accepted. The control plane evaluates its configured credentials; "
    "set AGENT_BOM_AWS_PROFILE on the server to choose a different one."
)


def ambient_cis_enabled() -> bool:
    """Whether an operator allows ambient-credential CIS evaluation.

    Read live so the flag can be flipped without a redeploy, matching how the
    cloud inventory surface resolves its own per-provider opt-ins.
    """
    return _flag_enabled(AMBIENT_CIS_ENV)


def ambient_snowflake_governance_enabled() -> bool:
    """Whether an operator allows reads of its own Snowflake account history.

    Governance and Cortex telemetry mine ACCESS_HISTORY, grants, tags and agent
    usage with the API process's ``SNOWFLAKE_*`` identity, so they share the
    ambient-credential bar rather than being a default viewer read.
    """
    return _flag_enabled(AMBIENT_SNOWFLAKE_GOVERNANCE_ENV)


def api_k8s_scans_enabled() -> bool:
    """Whether API callers may read Kubernetes with the server's service account or kubeconfig."""
    return _flag_enabled(API_K8S_SCANS_ENV)


def api_connector_scans_enabled() -> bool:
    """Whether API callers may reach SaaS connectors with the server's own tokens."""
    return _flag_enabled(API_CONNECTOR_SCANS_ENV)


def api_model_hub_credentials_enabled() -> bool:
    """Whether API callers may use the server's HF_TOKEN and Ollama host."""
    return _flag_enabled(API_MODEL_HUB_CREDENTIALS_ENV)


def allowed_k8s_contexts() -> frozenset[str]:
    """Kubeconfig contexts an operator lets API callers select (empty: none)."""
    raw = env_raw(API_K8S_CONTEXTS_ENV) or ""
    return frozenset(item.strip() for item in raw.split(",") if item.strip())


def ambient_tenant_permitted(tenant_id: str) -> bool:
    """Whether ``tenant_id`` may spend ambient credentials at all.

    Unset keeps the single-tenant default. A multi-tenant operator names the one
    tenant that owns the control plane's identity, so admins of every other
    tenant are refused regardless of their role.
    """
    bound = (env_raw(AMBIENT_TENANT_ENV) or "").strip()
    return not bound or bound == tenant_id


def ambient_disabled_note(flag: str, surface: str) -> str:
    """Fixed operator-facing text for a surface that is off."""
    return (
        f"{surface} uses this control plane's own credentials and is opt-in. An operator can set {flag}=1 on the API to let admins use it."
    )


def _flag_enabled(name: str) -> bool:
    return (env_raw(name) or "").strip().lower() in _TRUTHY


def configured_aws_profile() -> str | None:
    """Operator-selected AWS profile, if any. Never caller-supplied."""
    return (env_raw(AWS_PROFILE_ENV) or "").strip() or None


def disabled_payload(provider: str) -> dict[str, str]:
    """Envelope returned when ambient evaluation is not enabled.

    Carries ``error`` so headless callers that branch on it degrade the same way
    they do for a missing SDK, and ``status`` so operators can tell a disabled
    surface from a failed one.
    """
    return {
        "provider": provider,
        "status": "disabled",
        "error": DISABLED_NOTE,
    }
