import type {
  McpClientConfigAssignment,
  McpConfigAssignmentResponse,
  GatewayPolicy,
  GatewayPolicyResponse,
  GatewayAuditResponse,
  GatewayStatsResponse,
  GatewayFeedResponse,
  GatewayFeedKpis,
  EvaluateResult,
  DriftIncidentsResponse,
} from "./api-types";
import { get, post, put, del } from "./api-transport";

export const runtimeApi = {

  listRuntimeProfiles: () => get<{ assignments: McpClientConfigAssignment[] }>("/v1/mcp-config/assignments?include_revoked=true&limit=1000", { ttlMs: 0 }),

  createRuntimeProfile: (body: Record<string, unknown>) => post<McpConfigAssignmentResponse>("/v1/mcp-config/assignments", body),

  updateRuntimeProfile: (id: string, body: Record<string, unknown>) => put<McpConfigAssignmentResponse>(`/v1/mcp-config/assignments/${encodeURIComponent(id)}`, body),

  revokeRuntimeProfile: (id: string) => post<McpConfigAssignmentResponse>(`/v1/mcp-config/assignments/${encodeURIComponent(id)}/revoke`, {}),

  evaluateRuntimeProfile: (body: { config_id: string; issuer: string; environment: string; granted_scopes: string[]; upstream?: string; tool?: string }) =>
    post<{ profile_allowed: boolean; reason_code: string; scope: string; executed: boolean }>("/v1/runtime/profiles/evaluate", body),


  // ── Gateway ──
  listGatewayPolicies: () => get<GatewayPolicyResponse>("/v1/gateway/policies"),

  createGatewayPolicy: (body: Partial<GatewayPolicy>) =>
    post<GatewayPolicy>("/v1/gateway/policies", body),

  updateGatewayPolicy: (id: string, body: Partial<GatewayPolicy>) =>
    put<GatewayPolicy>(`/v1/gateway/policies/${id}`, body),

  deleteGatewayPolicy: (id: string) => del(`/v1/gateway/policies/${id}`),

  evaluateGateway: (body: { agent_name?: string; tool_name: string; arguments?: Record<string, unknown> }) =>
    post<EvaluateResult>("/v1/gateway/evaluate", body),

  listGatewayAudit: () => get<GatewayAuditResponse>("/v1/gateway/audit"),

  getGatewayStats: (fresh = false) => get<GatewayStatsResponse>("/v1/gateway/stats", fresh ? { ttlMs: 0 } : {}),

  getGatewayFeed: (limit = 100, cursor?: string) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (cursor) params.set("cursor", cursor);
    return get<GatewayFeedResponse>(`/v1/gateway/feed?${params}`, { ttlMs: 0 });
  },

  getGatewayFeedKpis: () => get<GatewayFeedKpis>("/v1/gateway/feed/kpis"),


  // ── Drift / behavior-incident cockpit ──
  listDriftIncidents: (includeResolved = false, limit = 200) =>
    get<DriftIncidentsResponse>(`/v1/runtime/drift/incidents?include_resolved=${includeResolved}&limit=${limit}`),

  resolveDriftIncident: (incidentId: string, note?: string) =>
    post<{ resolved: boolean }>(`/v1/runtime/drift/incidents/${encodeURIComponent(incidentId)}/resolve`, { note: note ?? "" }),
};
