import type {
  TraceConnectorPullResponse,
  HealthResponse,
  ActivityTimeline,
  TraceIngestResponse,
  TraceExplorerResponse,
  HitlApprovalQueueResponse,
  ProxyStatusResponse,
  ProxyAlertsResponse,
  CostReport,
  AnomaliesReport,
  CostForecast,
} from "./api-types";
import { get, post } from "./api-transport";

export const observabilityApi = {

  // Activity Timeline
  getActivity: (days = 30) => get<ActivityTimeline>(`/v1/activity?days=${days}`),

  traceCollectionStatus: (connectionId: string, signal?: AbortSignal) => get<import("./api-types").TraceCollectionReceipt>(`/v1/traces/connectors/langfuse/collection?connection_id=${encodeURIComponent(connectionId)}`, signal ? { signal } : {}),

  collectTracePage: (connectionId: string, signal?: AbortSignal) => post<import("./api-types").TraceCollectionReceipt>("/v1/traces/connectors/langfuse/collect", { connection_id: connectionId }, {}, signal, 60000),

  systemHealth: () => get<HealthResponse>("/v1/system/health"),

  listTraceConnectors: () => get<import("./api-types").TraceConnectorsResponse>("/v1/traces/connectors"),

  pullTraceConnector: (provider: "langfuse" | "langsmith", body: ({ credentials: Record<string, string>; connection_id?: never } | { connection_id: string; credentials?: never }) & { limit: number; screen_content: boolean; max_pages?: number; import_id?: string; window_start?: string; window_end?: string }, signal?: AbortSignal) => post<TraceConnectorPullResponse>(`/v1/traces/connectors/${provider}/pull`, body, {}, signal, 60000),

  ingestTraces: (body: unknown) => post<TraceIngestResponse>("/v1/traces", body),

  getRuntimeObservationRevisions: (observationId: string, offset = 0) =>
    get<{ count: number; limit: number; offset: number; observations: Array<{ observed_at: string; verdict: string; metadata: Record<string, unknown> }> }>(`/v1/runtime/observation-revisions?observation_id=${encodeURIComponent(observationId)}&limit=25&offset=${offset}`),

  getTraceExplorer: (limit = 100, scanId?: string, filters?: { offset?: number; agent_name?: string | undefined; source?: string | undefined; session_id?: string; connection_id?: string }) => {
    const query = new URLSearchParams({ limit: String(limit) });
    if (scanId) query.set("scan_id", scanId);
    for (const [key, value] of Object.entries(filters ?? {})) {
      if (value !== undefined && value !== "") query.set(key, String(value));
    }
    return get<TraceExplorerResponse>(`/v1/runtime/trace-explorer?${query}`);
  },

  getHitlApprovalQueue: (status?: string, limit = 100) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (status) params.set("status", status);
    return get<HitlApprovalQueueResponse>(`/v1/runtime/approval-queue?${params}`);
  },

  decideHitlApproval: (itemId: string, decision: "approve" | "deny", note = "") =>
    post<{ schema_version: string; item: HitlApprovalQueueResponse["items"][number] }>(
      `/v1/runtime/approval-queue/${encodeURIComponent(itemId)}/decision`,
      { decision, note },
    ),


  // ── Proxy Runtime ──
  getProxyStatus: () => get<ProxyStatusResponse>("/v1/proxy/status"),

  getProxyAlerts: (filters?: { severity?: string; detector?: string; limit?: number }) => {
    const params = new URLSearchParams();
    if (filters?.severity) params.set("severity", filters.severity);
    if (filters?.detector) params.set("detector", filters.detector);
    if (filters?.limit) params.set("limit", String(filters.limit));
    const qs = params.toString();
    return get<ProxyAlertsResponse>(`/v1/proxy/alerts${qs ? `?${qs}` : ""}`);
  },


  // ── Cost / FinOps cockpit ──
  getCostReport: (filters?: { agent?: string; costCenter?: string; tag?: string }) => {
    const params = new URLSearchParams();
    if (filters?.agent) params.set("agent", filters.agent);
    if (filters?.costCenter) params.set("cost_center", filters.costCenter);
    if (filters?.tag) params.set("tag", filters.tag);
    const qs = params.toString();
    return get<CostReport>(`/v1/observability/costs${qs ? `?${qs}` : ""}`, { ttlMs: 0 });
  },

  /** Forward-looking burn-rate + budget-runway projection (reference only) */
  getCostForecast: (agent?: string) =>
    get<CostForecast>(`/v1/observability/costs/forecast${agent ? `?agent=${encodeURIComponent(agent)}` : ""}`, { ttlMs: 0 }),

  getCostAnomalies: (zThreshold?: number) =>
    get<AnomaliesReport>(`/v1/observability/anomalies${zThreshold ? `?z_threshold=${zThreshold}` : ""}`, { ttlMs: 0 }),
};
