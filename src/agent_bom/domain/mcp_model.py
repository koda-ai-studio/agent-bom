"""Core data models for AI-BOM inventory."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional
from uuid import UUID

from agent_bom.canonical_ids import (
    canonical_mcp_prompt_id,
    canonical_mcp_resource_id,
    canonical_mcp_server_id,
    canonical_mcp_tool_id,
    mcp_server_fingerprint,
)
from agent_bom.core.packages import normalize_package_name as normalize_package_name
from agent_bom.core.severity import Severity as Severity
from agent_bom.domain.inventory_types import ServerSurface, TransportType
from agent_bom.domain.package_model import Package
from agent_bom.package_utils import parse_debian_source_name as parse_debian_source_name  # noqa: F401


@dataclass
class MCPTool:
    """A tool exposed by an MCP server."""

    name: str
    description: str
    discovery_source: Optional[str] = None
    discovery_confidence: Optional[str] = None
    input_schema: dict[str, Any] | bool | None = None
    output_schema: dict[str, Any] | bool | None = None
    annotations: dict[str, Any] = field(default_factory=dict)
    ui_metadata: dict[str, Any] = field(default_factory=dict)
    declared_capabilities: list[str] = field(default_factory=list)
    schema_findings: list[str] = field(default_factory=list)
    schema_rule_findings: list[dict[str, Any]] = field(default_factory=list)
    server_canonical_id: Optional[str] = None  # Owning server scope (stamped by MCPServer)

    @property
    def stable_id(self) -> str:
        """Deterministic ID for this MCP tool, scoped to its owning server."""
        return canonical_mcp_tool_id(self.name, self.input_schema, server_id=self.server_canonical_id)

    @property
    def canonical_id(self) -> str:
        """Canonical alias for stable_id used by report and graph consumers."""
        return self.stable_id

    @property
    def fingerprint(self) -> str:
        return self.stable_id

    @property
    def risk_score(self) -> int:
        """Heuristic risk score for the tool based on schema findings."""
        score = 0
        for finding in self.schema_findings:
            if "shell-execution-capability" in finding:
                score += 4
            elif "network-egress-capability" in finding:
                score += 3
            elif "filesystem-capability" in finding:
                score += 2
            else:
                score += 1
        return min(score, 10)


@dataclass
class MCPResource:
    """A resource exposed by an MCP server."""

    uri: str
    name: str
    description: str = ""
    mime_type: Optional[str] = None
    content_findings: list[str] = field(default_factory=list)
    server_canonical_id: Optional[str] = None  # Owning server scope (stamped by MCPServer)

    @property
    def stable_id(self) -> str:
        """Deterministic ID for this MCP resource, scoped to its owning server."""
        return canonical_mcp_resource_id(self.uri, self.mime_type, server_id=self.server_canonical_id)

    @property
    def canonical_id(self) -> str:
        """Canonical alias for stable_id used by report and graph consumers."""
        return self.stable_id

    @property
    def fingerprint(self) -> str:
        return self.stable_id

    @property
    def risk_score(self) -> int:
        """Heuristic risk score for the resource based on content findings."""
        score = 0
        for finding in self.content_findings:
            if "hidden-instruction-surface" in finding or "prompt-bearing-resource" in finding:
                score += 3
            elif "mutable-resource" in finding:
                score += 2
            else:
                score += 1
        return min(score, 10)


@dataclass
class MCPPrompt:
    """A prompt template exposed by an MCP server."""

    name: str
    description: str = ""
    arguments: list[dict[str, object]] = field(default_factory=list)
    content_findings: list[str] = field(default_factory=list)
    server_canonical_id: Optional[str] = None  # Owning server scope (stamped by MCPServer)

    @property
    def stable_id(self) -> str:
        """Deterministic ID for this MCP prompt descriptor, scoped to its owning server."""
        return canonical_mcp_prompt_id(self.name, self.arguments, server_id=self.server_canonical_id)

    @property
    def canonical_id(self) -> str:
        """Canonical alias for stable_id used by report and graph consumers."""
        return self.stable_id

    @property
    def fingerprint(self) -> str:
        return self.stable_id

    @property
    def risk_score(self) -> int:
        """Heuristic risk score for prompt metadata findings."""
        score = 0
        for finding in self.content_findings:
            if "system-prompt-surface" in finding or "hidden-instruction-surface" in finding:
                score += 3
            elif "required-freeform-argument" in finding:
                score += 2
            else:
                score += 1
        return min(score, 10)


@dataclass
class PermissionProfile:
    """Privilege and permission profile for an MCP server or container."""

    runs_as_root: bool = False
    container_privileged: bool = False
    tool_permissions: dict[str, str] = field(default_factory=dict)  # tool -> "read"|"write"|"execute"|"destructive"
    capabilities: list[str] = field(default_factory=list)  # Linux caps: CAP_SYS_ADMIN, etc.
    network_access: bool = False
    filesystem_write: bool = False
    shell_access: bool = False
    security_opt: list[str] = field(default_factory=list)

    @property
    def is_elevated(self) -> bool:
        """True if server has any elevated privileges."""
        return self.runs_as_root or self.container_privileged or self.shell_access or bool(self.capabilities)

    @property
    def privilege_level(self) -> str:
        """Summarize privilege level as critical/high/medium/low."""
        if self.container_privileged or "CAP_SYS_ADMIN" in self.capabilities:
            return "critical"
        if self.runs_as_root or self.shell_access:
            return "high"
        if self.filesystem_write or self.network_access or self.capabilities:
            return "medium"
        return "low"


@dataclass(frozen=True)
class CredentialIdentityBinding:
    """Explicit, non-secret evidence joining a credential slot to an identity.

    Environment-variable names alone are not identity evidence.  Producers may
    populate this contract only when a configuration or provider observation
    names both sides of the relationship.
    """

    credential_ref: str
    identity_canonical_id: str
    evidence_source: str
    provider: Optional[str] = None

    def __post_init__(self) -> None:
        for field_name in ("credential_ref", "identity_canonical_id", "evidence_source"):
            normalized = str(getattr(self, field_name) or "").strip()
            if not normalized:
                raise ValueError(f"{field_name} is required")
            object.__setattr__(self, field_name, normalized)
        if self.provider is not None:
            object.__setattr__(self, "provider", str(self.provider).strip().lower() or None)

    def to_dict(self) -> dict[str, str | None]:
        return {
            "credential_ref": self.credential_ref,
            "identity_canonical_id": self.identity_canonical_id,
            "evidence_source": self.evidence_source,
            "provider": self.provider,
        }


# Discovery source stamped on SBOM components declared as ``agent-bom:type=mcp-server``.
SBOM_DECLARED_MCP_SOURCE = "sbom:mcp-server"


@dataclass
class MCPServer:
    """An MCP server with its tools, resources, and dependencies."""

    name: str
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    transport: TransportType = TransportType.STDIO
    url: Optional[str] = None  # For SSE/HTTP transports
    tools: list[MCPTool] = field(default_factory=list)
    resources: list[MCPResource] = field(default_factory=list)
    prompts: list[MCPPrompt] = field(default_factory=list)
    packages: list[Package] = field(default_factory=list)
    config_path: Optional[str] = None  # Where this server was discovered
    connection_metadata: dict[str, Any] = field(default_factory=dict)
    working_dir: Optional[str] = None  # Server's working directory
    mcp_version: Optional[str] = None  # MCP protocol version (e.g. "2024-11-05")
    registry_verified: bool = False  # True if found in agent-bom MCP registry
    registry_id: Optional[str] = None  # Registry entry ID, e.g. "modelcontextprotocol/filesystem"
    permission_profile: Optional[PermissionProfile] = None
    security_blocked: bool = False  # True if server was rejected for security reasons
    security_warnings: list[str] = field(default_factory=list)  # Security issues found during discovery
    security_intelligence: list[dict[str, object]] = field(default_factory=list)
    surface: ServerSurface = ServerSurface.MCP
    discovery_sources: list[str] = field(default_factory=list)
    discovery_provenance: Optional[dict[str, Any]] = None  # Sanitized discovery provenance contract for this server asset
    identity_bindings: list[CredentialIdentityBinding] = field(default_factory=list)
    imported_canonical_id: Optional[str] = None  # Declared SBOM identity; never authorizes execution or trust.

    def __post_init__(self) -> None:
        """Scope child tool/resource/prompt identities to this server."""
        self.stamp_child_identities()

    def stamp_child_identities(self) -> None:
        """Stamp owned tools/resources/prompts with this server's canonical id.

        Child ids are scoped to their owning server so a same-named tool on two
        different servers never collides onto one identity. Call again after
        mutating ``command``/``url``/``registry_id`` or appending children.
        """
        scope = self.canonical_id
        for child in (*self.tools, *self.resources, *self.prompts):
            # Some legacy paths populate these lists with plain dicts; only model
            # objects carry the scope field.
            if hasattr(child, "server_canonical_id"):
                child.server_canonical_id = scope

    @property
    def stable_id(self) -> str:
        """Deterministic ID for this MCP server.

        Configured endpoints and exact launch recipes remain distinct even
        when they share a registry artifact. Stdio context includes working
        directory and environment in the opaque identity, never plaintext.
        """
        if self.surface == ServerSurface.SBOM and self.command == "sbom" and self.imported_canonical_id:
            try:
                declared = UUID(self.imported_canonical_id)
                if declared.version == 5 and str(declared) == self.imported_canonical_id:
                    return self.imported_canonical_id
            except (ValueError, AttributeError):
                pass
        return canonical_mcp_server_id(
            self.name,
            self.command,
            registry_id=self.registry_id,
            url=self.url,
            args=self.args,
            working_dir=self.working_dir,
            environment=self.env,
        )

    @property
    def canonical_id(self) -> str:
        """Canonical alias for stable_id used by report and graph consumers."""
        return self.stable_id

    @property
    def auth_mode(self) -> str:
        """Best-effort auth posture classification for the server."""
        if self.connection_metadata.get("header_names") or self.connection_metadata.get("oauth_configured"):
            return "configured-http-auth"
        credential_names = self.credential_names
        if credential_names:
            return "env-credentials"
        if self.url and "@" in self.url:
            return "url-embedded-credentials"
        if self.url:
            return "network-no-auth-observed"
        return "local-stdio"

    @property
    def fingerprint(self) -> str:
        """Deterministic runtime/config fingerprint for the server."""
        return mcp_server_fingerprint(self)

    @property
    def vulnerable_packages(self) -> list[Package]:
        return [p for p in self.packages if p.has_vulnerabilities]

    @property
    def total_vulnerabilities(self) -> int:
        return sum(len(p.vulnerabilities) for p in self.packages)

    @property
    def has_credentials(self) -> bool:
        """Check if env vars suggest credentials are present."""
        from agent_bom.constants import is_credential_key

        return any(is_credential_key(key) for key in self.env)

    @property
    def credential_names(self) -> list[str]:
        """Return names of env vars that look like credentials."""
        from agent_bom.constants import is_credential_key

        return [key for key in self.env if is_credential_key(key)]

    @property
    def is_mcp_surface(self) -> bool:
        """True only for real MCP servers, not synthetic scan wrappers."""
        return self.surface == ServerSurface.MCP

    @property
    def counts_as_mcp_server(self) -> bool:
        """A real MCP server, including one declared as an MCP server in an imported SBOM.

        Imported servers keep the SBOM surface (identity, never executed) but
        still count in the MCP inventory, so re-scanning a BOM preserves it.
        """
        return self.is_mcp_surface or (self.surface == ServerSurface.SBOM and SBOM_DECLARED_MCP_SOURCE in self.discovery_sources)

    @property
    def allows_registry_resolution(self) -> bool:
        """Whether MCP registry/marketplace fallback is valid for this surface."""
        return self.surface == ServerSurface.MCP
