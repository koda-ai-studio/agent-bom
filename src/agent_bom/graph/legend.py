"""Display metadata for canonical graph entities and recorded relationships."""

from dataclasses import dataclass

from agent_bom.graph.types import GraphSemanticLayer

# ═══════════════════════════════════════════════════════════════════════════
# Graph filter options & legend
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(slots=True)
class LegendEntry:
    """Single entry in the graph legend."""

    key: str
    label: str
    color: str
    shape: str = "circle"  # circle / diamond / square / triangle
    layer: str = ""


# Entity legend
ENTITY_LEGEND: list[LegendEntry] = [
    LegendEntry(key="agent", label="AI Agent", color="#10b981", shape="circle", layer=GraphSemanticLayer.ORCHESTRATION.value),
    LegendEntry(key="server", label="MCP Server", color="#3b82f6", shape="circle", layer=GraphSemanticLayer.MCP_SERVER.value),
    LegendEntry(key="package", label="Package", color="#52525b", shape="square", layer=GraphSemanticLayer.PACKAGE.value),
    LegendEntry(key="tool", label="Tool", color="#a855f7", shape="diamond", layer=GraphSemanticLayer.TOOL.value),
    LegendEntry(key="tool_call", label="Tool Call", color="#c084fc", shape="diamond", layer=GraphSemanticLayer.RUNTIME_EVIDENCE.value),
    LegendEntry(key="vulnerability", label="Vulnerability", color="#ef4444", shape="triangle", layer=GraphSemanticLayer.FINDING.value),
    LegendEntry(key="credential", label="Credential", color="#f59e0b", shape="diamond", layer=GraphSemanticLayer.IDENTITY.value),
    LegendEntry(
        key="credential_ref",
        label="Credential Reference",
        color="#fbbf24",
        shape="diamond",
        layer=GraphSemanticLayer.IDENTITY.value,
    ),
    LegendEntry(
        key="misconfiguration", label="Misconfiguration", color="#f97316", shape="triangle", layer=GraphSemanticLayer.FINDING.value
    ),
    LegendEntry(key="model", label="Model", color="#8b5cf6", shape="square", layer=GraphSemanticLayer.ASSET.value),
    LegendEntry(
        key="framework",
        label="AI Framework",
        color="#06b6d4",
        shape="square",
        layer=GraphSemanticLayer.ORCHESTRATION.value,
    ),
    LegendEntry(key="container", label="Container", color="#6366f1", shape="square", layer=GraphSemanticLayer.INFRA.value),
    LegendEntry(key="cloud_resource", label="Cloud Resource", color="#0ea5e9", shape="square", layer=GraphSemanticLayer.INFRA.value),
    LegendEntry(key="resource", label="Resource", color="#38bdf8", shape="square", layer=GraphSemanticLayer.ASSET.value),
    LegendEntry(key="directory", label="Directory", color="#0d9488", shape="square", layer=GraphSemanticLayer.CODE.value),
    LegendEntry(key="source_file", label="Source File", color="#22d3ee", shape="square", layer=GraphSemanticLayer.CODE.value),
    LegendEntry(key="code_module", label="Code Module", color="#06b6d4", shape="circle", layer=GraphSemanticLayer.CODE.value),
    LegendEntry(key="config_file", label="Config File", color="#f97316", shape="square", layer=GraphSemanticLayer.CODE.value),
    LegendEntry(key="external_import", label="External Import", color="#f59e0b", shape="circle", layer=GraphSemanticLayer.CODE.value),
    LegendEntry(key="ci_job", label="CI/CD Job", color="#a855f7", shape="diamond", layer=GraphSemanticLayer.CI.value),
    LegendEntry(key="org", label="Organization", color="#115e59", shape="square", layer=GraphSemanticLayer.IDENTITY.value),
    LegendEntry(key="account", label="Account", color="#0f766e", shape="square", layer=GraphSemanticLayer.IDENTITY.value),
    LegendEntry(key="user", label="User", color="#14b8a6", shape="circle", layer=GraphSemanticLayer.USER.value),
    LegendEntry(key="group", label="Group", color="#0d9488", shape="circle", layer=GraphSemanticLayer.IDENTITY.value),
    LegendEntry(key="role", label="Role", color="#ea580c", shape="circle", layer=GraphSemanticLayer.IDENTITY.value),
    LegendEntry(key="policy", label="Policy", color="#d97706", shape="diamond", layer=GraphSemanticLayer.IDENTITY.value),
    LegendEntry(key="service_account", label="Service Account", color="#0f766e", shape="circle", layer=GraphSemanticLayer.IDENTITY.value),
    LegendEntry(
        key="service_principal", label="Service Principal", color="#0f766e", shape="circle", layer=GraphSemanticLayer.IDENTITY.value
    ),
    LegendEntry(
        key="federated_identity",
        label="Federated Identity",
        color="#0e7490",
        shape="circle",
        layer=GraphSemanticLayer.IDENTITY.value,
    ),
    LegendEntry(key="fleet", label="Fleet", color="#6b7280", shape="square", layer=GraphSemanticLayer.INFRA.value),
    LegendEntry(key="cluster", label="Cluster", color="#4b5563", shape="square", layer=GraphSemanticLayer.INFRA.value),
    LegendEntry(key="dataset", label="Dataset", color="#06b6d4", shape="square", layer=GraphSemanticLayer.ASSET.value),
    LegendEntry(key="environment", label="Environment", color="#9ca3af", shape="square", layer=GraphSemanticLayer.INFRA.value),
    LegendEntry(key="provider", label="Provider", color="#d1d5db", shape="square", layer=GraphSemanticLayer.INFRA.value),
    LegendEntry(key="managed_identity", label="Managed Identity", color="#0891b2", shape="circle", layer=GraphSemanticLayer.IDENTITY.value),
    LegendEntry(key="access_grant", label="Access Grant", color="#ca8a04", shape="diamond", layer=GraphSemanticLayer.IDENTITY.value),
    LegendEntry(key="access_policy", label="Access Policy", color="#a16207", shape="diamond", layer=GraphSemanticLayer.IDENTITY.value),
    LegendEntry(key="drift_incident", label="Drift Incident", color="#fb923c", shape="triangle", layer=GraphSemanticLayer.FINDING.value),
    LegendEntry(key="data_store", label="Data Store", color="#0284c7", shape="square", layer=GraphSemanticLayer.ASSET.value),
    LegendEntry(key="application", label="Application", color="#7c3aed", shape="circle", layer=GraphSemanticLayer.APP.value),
    LegendEntry(key="api_gateway", label="API Gateway", color="#2563eb", shape="diamond", layer=GraphSemanticLayer.API_GATEWAY.value),
    LegendEntry(key="blueprint", label="Blueprint", color="#818cf8", shape="square", layer=GraphSemanticLayer.ORCHESTRATION.value),
]

RELATIONSHIP_LEGEND: list[LegendEntry] = [
    # Static inventory
    LegendEntry(key="hosts", label="Hosts", color="#6b7280"),
    LegendEntry(key="hosted_on", label="Hosted On", color="#78716c"),
    LegendEntry(key="uses", label="Uses", color="#10b981"),
    LegendEntry(key="uses_framework", label="Uses Framework", color="#06b6d4"),
    LegendEntry(key="depends_on", label="Depends On", color="#52525b"),
    LegendEntry(key="provides_tool", label="Provides Tool", color="#a855f7"),
    LegendEntry(key="exposes_cred", label="Exposes Credential", color="#f59e0b"),
    LegendEntry(key="reaches_tool", label="Credential Reaches Tool", color="#fbbf24"),
    LegendEntry(key="serves_model", label="Serves Model", color="#8b5cf6"),
    LegendEntry(key="contains", label="Contains", color="#6366f1"),
    LegendEntry(key="imports", label="Imports", color="#22d3ee"),
    LegendEntry(key="defines", label="Defines", color="#06b6d4"),
    LegendEntry(key="runs", label="Runs", color="#a855f7"),
    LegendEntry(key="configures", label="Configures", color="#f97316"),
    LegendEntry(key="observes", label="Observes", color="#22d3ee"),
    # Vulnerability
    LegendEntry(key="vulnerable_to", label="Vulnerable To", color="#ef4444"),
    LegendEntry(key="affects", label="Affects", color="#dc2626"),
    LegendEntry(key="exploitable_via", label="Exploitable Via", color="#b91c1c"),
    LegendEntry(key="remediates", label="Remediates", color="#22c55e"),
    LegendEntry(key="triggers", label="Triggers", color="#f97316"),
    # Lateral movement
    LegendEntry(key="shares_server", label="Shares Server", color="#22d3ee"),
    LegendEntry(key="shares_cred", label="Shares Credential", color="#f97316"),
    LegendEntry(key="lateral_path", label="Lateral Path", color="#ea580c"),
    # Ownership
    LegendEntry(key="manages", label="Manages", color="#14b8a6"),
    LegendEntry(key="owns", label="Owns", color="#0d9488"),
    LegendEntry(key="part_of", label="Part Of", color="#6b7280"),
    LegendEntry(key="member_of", label="Member Of", color="#4b5563"),
    LegendEntry(key="assumes", label="Assumes", color="#ea580c"),
    LegendEntry(key="trusts", label="Trusts", color="#0891b2"),
    LegendEntry(key="attached", label="Attached", color="#d97706"),
    LegendEntry(key="inherits", label="Inherits", color="#a16207"),
    LegendEntry(key="can_access", label="Can Access", color="#dc2626"),
    LegendEntry(key="cross_account_trust", label="Cross-Account Trust", color="#be123c"),
    # Runtime
    LegendEntry(key="acted_as", label="Acted As (runtime)", color="#14b8a6"),
    LegendEntry(key="invoked", label="Invoked (runtime)", color="#10b981"),
    LegendEntry(key="called", label="Called (runtime)", color="#c084fc"),
    LegendEntry(key="used_credential", label="Used Credential (runtime)", color="#fbbf24"),
    LegendEntry(key="accessed", label="Accessed (runtime)", color="#3b82f6"),
    LegendEntry(key="delegated_to", label="Delegated To (runtime)", color="#a855f7"),
    LegendEntry(key="recorded_activity", label="Recorded Activity (execution unconfirmed)", color="#64748b"),
    LegendEntry(key="trace_step", label="Trace Step (recorded)", color="#6366f1"),
    # Cross-environment correlation (#1892)
    LegendEntry(key="correlates_with", label="Correlates With (cross-env)", color="#0ea5e9"),
    LegendEntry(key="possibly_correlates_with", label="Possibly Correlates With (low confidence)", color="#7dd3fc"),
    # Agent-identity governance
    LegendEntry(key="authenticates_as", label="Authenticates As", color="#0891b2"),
    LegendEntry(key="scoped_to", label="Scoped To", color="#22d3ee"),
    LegendEntry(key="governs", label="Governs", color="#a16207"),
    LegendEntry(key="exhibits_drift", label="Exhibits Drift", color="#fb923c"),
    # Cloud-CNAPP
    LegendEntry(key="exposed_to", label="Exposed To", color="#e11d48"),
    LegendEntry(key="stores", label="Stores", color="#0284c7"),
    LegendEntry(key="has_permission", label="Has Permission", color="#dc2626"),
    LegendEntry(key="protects", label="Protects (WAF/gateway)", color="#2563eb"),
    # ASPM
    LegendEntry(key="belongs_to", label="Belongs To (application)", color="#7c3aed"),
]
