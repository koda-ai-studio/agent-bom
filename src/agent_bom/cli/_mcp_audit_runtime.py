"""Runtime dependencies for the lazy MCP audit CLI command."""

from agent_bom import discovery as discovery
from agent_bom import mcp_introspect as mcp_introspect
from agent_bom.mcp_auth_posture import evaluate_mcp_auth_posture as evaluate_mcp_auth_posture
from agent_bom.mcp_introspect import IntrospectionError as IntrospectionError
from agent_bom.models import AIBOMReport as AIBOMReport
from agent_bom.output.json_fmt import to_json as to_json
from agent_bom.output.sarif import to_sarif as to_sarif
from agent_bom.scanners.mcp_audit import audit_mcp_agents as audit_mcp_agents
from agent_bom.security import sanitize_error as sanitize_error
