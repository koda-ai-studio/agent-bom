"""Core data models for AI-BOM inventory."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from agent_bom.core.packages import normalize_package_name as normalize_package_name
from agent_bom.core.severity import Severity as Severity
from agent_bom.package_utils import parse_debian_source_name as parse_debian_source_name  # noqa: F401


def _utc_now_iso() -> str:
    """Return a UTC ISO-8601 timestamp for discovery lifecycle defaults."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class AgentType(str, Enum):
    CLAUDE_DESKTOP = "claude-desktop"
    CLAUDE_CODE = "claude-code"
    CURSOR = "cursor"
    WINDSURF = "windsurf"
    CLINE = "cline"
    VSCODE_COPILOT = "vscode-copilot"
    CORTEX_CODE = "cortex-code"  # Snowflake Cortex Code CLI (CoCo)
    CODEX_CLI = "codex-cli"  # OpenAI Codex CLI
    GEMINI_CLI = "gemini-cli"  # Google Gemini CLI
    GOOSE = "goose"  # Block Goose AI agent
    SNOWFLAKE_CLI = "snowflake-cli"  # Snowflake CLI (snow)
    CONTINUE = "continue"  # Continue.dev
    ZED = "zed"  # Zed editor
    OPENCLAW = "openclaw"  # OpenClaw AI agent
    ROO_CODE = "roo-code"  # Roo Code (VS Code extension)
    AMAZON_Q = "amazon-q"  # Amazon Q Developer (VS Code)
    DOCKER_MCP = "docker-mcp"  # Docker Desktop MCP Toolkit
    JETBRAINS_AI = "jetbrains-ai"  # JetBrains AI Assistant (IntelliJ, PyCharm, etc.)
    JUNIE = "junie"  # JetBrains Junie coding agent
    COPILOT_CLI = "copilot-cli"  # GitHub Copilot CLI (standalone)
    TABNINE = "tabnine"  # Tabnine AI assistant
    SOURCEGRAPH_CODY = "sourcegraph-cody"  # Sourcegraph Cody AI assistant
    AIDER = "aider"  # Aider AI pair programming
    REPLIT_AGENT = "replit-agent"  # Replit Agent
    VOID_EDITOR = "void"  # Void editor (open-source Cursor alternative)
    AIDE = "aide"  # Aide AI IDE (VS Code fork)
    TRAE = "trae"  # Trae AI IDE (ByteDance)
    PIECES = "pieces"  # Pieces for Developers
    MCP_CLI = "mcp-cli"  # mcp-cli standalone tool
    CUSTOM = "custom"


class TransportType(str, Enum):
    STDIO = "stdio"
    SSE = "sse"
    STREAMABLE_HTTP = "streamable-http"
    UNKNOWN = "unknown"


class ServerSurface(str, Enum):
    MCP = "mcp-server"
    CONTAINER_IMAGE = "container-image"
    OCI_TARBALL = "oci-tarball"
    FILESYSTEM = "filesystem"
    SBOM = "sbom"
    EXTERNAL_SCAN = "external-scan"
    OS_PACKAGES = "os-packages"
    SAST = "sast"
    AI_INVENTORY = "ai-inventory"
    OTHER = "other"


class AgentStatus(str, Enum):
    CONFIGURED = "configured"
    INSTALLED_NOT_CONFIGURED = "installed-not-configured"
