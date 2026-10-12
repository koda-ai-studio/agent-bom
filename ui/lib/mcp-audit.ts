import type { UnifiedFinding } from './api-types';

export interface McpAuditSurface {
  status: string;
  discovered?: number;
  inspected?: number;
  reason?: string;
}

export interface McpAuditCoverage {
  server_name: string;
  server_identity: string;
  server_canonical_id?: string;
  agent_name: string;
  tools: McpAuditSurface;
  resources: McpAuditSurface;
  prompts: McpAuditSurface;
  permission_scope?: McpAuditSurface;
}

export function mcpAuditFindings(findings: UnifiedFinding[] = []): UnifiedFinding[] {
  return [...new Map(findings.filter(f => f.source === 'MCP_SCAN' && (f.evidence?.detector === 'mcp_enforcement' || f.evidence?.mcp_auth_weakness || f.evidence?.mcp_tool_rule)).map(f => [f.id, f])).values()];
}

/** Operator-reviewed draft for one upstream. No policy mutation occurs here. */
export function proposedToolRestriction(finding: UnifiedFinding): string | null {
  const evidence = finding.evidence;
  if (evidence?.category !== 'over_permission' || typeof evidence.server_canonical_id !== 'string') return null;
  const raw = evidence.affected_tools;
  if (!Array.isArray(raw)) return null;
  const tools = [...new Set(raw.filter((value): value is string => typeof value === 'string' && value.length > 0 && value !== '*'))].sort();
  if (!tools.length) return null;
  return JSON.stringify({ rules: [{ id: 'review-excess-capabilities', action: 'block', block_tools: tools }] }, null, 2);
}
