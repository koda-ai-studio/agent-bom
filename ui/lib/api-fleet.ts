import type {
  EndpointConnection,
  EndpointConnectionCreate,
  EndpointConnections,
  EndpointInventory,
  EndpointSync,
} from "./endpoint-connectors";
import type {
  FleetResponse,
  FleetQuarantineResult,
  FleetStatsResponse,
  FleetSyncResult,
  FleetEndpointsResponse,
} from "./api-types";
import { get, post, put, patch } from "./api-transport";

export const fleetApi = {

  /** Fleet management */
  listFleet: (filters?: {
    state?: string | undefined;
    environment?: string | undefined;
    min_trust?: number | undefined;
    search?: string | undefined;
    include_quarantined?: boolean | undefined;
    limit?: number | undefined;
    offset?: number | undefined;
  }) => {
    const params = new URLSearchParams();
    if (filters?.state) params.set("state", filters.state);
    if (filters?.environment) params.set("environment", filters.environment);
    if (filters?.min_trust != null) params.set("min_trust", String(filters.min_trust));
    if (filters?.search) params.set("search", filters.search);
    if (filters?.include_quarantined) params.set("include_quarantined", "true");
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    const qs = params.toString();
    return get<FleetResponse>(`/v1/fleet${qs ? `?${qs}` : ""}`);
  },

  syncFleet: () => post<FleetSyncResult>("/v1/fleet/sync", {}),

  updateFleetState: (agentId: string, state: string, reason?: string) =>
    put<unknown>(`/v1/fleet/${agentId}/state`, { state, reason: reason ?? "" }),

  /**
   * One-click containment: quarantine the agent AND mint an enforce-mode
   * gateway deny policy bound to its identity (fail closed, idempotent).
   */
  quarantineFleetAgent: (agentId: string) =>
    post<FleetQuarantineResult>(`/v1/fleet/${encodeURIComponent(agentId)}/quarantine`, {}),

  getFleetStats: () => get<FleetStatsResponse>("/v1/fleet/stats"),

  listFleetEndpoints: (filters?: {
    search?: string | undefined;
    completeness?: "complete" | "partial" | undefined;
    limit?: number | undefined;
    offset?: number | undefined;
  }) => {
    const params = new URLSearchParams();
    if (filters?.search) params.set("search", filters.search);
    if (filters?.completeness) params.set("completeness", filters.completeness);
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    const qs = params.toString();
    return get<FleetEndpointsResponse>(`/v1/fleet/endpoints${qs ? `?${qs}` : ""}`);
  },


  // ── Connectors / sources ──
  bindEndpointAgent: (deviceId: string, agentId: string, active = true) => put<{agent_id: string; active: boolean; assurance: string}>(`/v1/endpoint-connectors/devices/${encodeURIComponent(deviceId)}/agent-binding`, {agent_id: agentId, active}),

  endpointConnections: () => get<EndpointConnections>("/v1/endpoint-connectors"),

  createEndpointConnection: (body: EndpointConnectionCreate) => post<EndpointConnection>("/v1/endpoint-connectors", body),

  updateEndpointConnection: (id: string, body: {enabled?: boolean; client_secret?: string}) => patch<EndpointConnection>(`/v1/endpoint-connectors/${encodeURIComponent(id)}`, body),

  syncEndpointConnection: (id: string, restart = false) => post<EndpointSync>(`/v1/endpoint-connectors/${encodeURIComponent(id)}/sync`, {restart, max_pages: 5}, {}, undefined, 180_000),

  endpointDevices: (id: string, offset = 0) => get<EndpointInventory>(`/v1/endpoint-connectors/${encodeURIComponent(id)}/devices?limit=10&offset=${offset}`),
};
