import type {
  AgentBomManifestResponse,
  AgentsResponse,
  RegistryServer,
  RegistryResponse,
  AgentDetailResponse,
  AgentLifecycleResponse,
} from "./api-types";
import { get } from "./api-transport";

export type AgentSortKey = "name" | "servers" | "packages" | "credentials" | "findings";

export interface AgentListParams {
  limit?: number;
  offset?: number;
  q?: string;
  type?: string[];
  status?: string[];
  source?: string[];
  sort?: AgentSortKey | null;
  order?: "asc" | "desc";
}

export interface RegistryListParams {
  limit?: number;
  offset?: number;
  q?: string;
  risk?: string[];
  category?: string[];
}

export function agentListQueryString(params: AgentListParams): string {
  const query = new URLSearchParams();
  if (params.limit != null) query.set("limit", String(params.limit));
  if (params.offset) query.set("offset", String(params.offset));
  if (params.q?.trim()) query.set("q", params.q.trim());
  for (const key of ["type", "status", "source"] as const) {
    for (const value of params[key] ?? []) query.append(key, value);
  }
  if (params.sort) {
    query.set("sort", params.sort);
    if (params.order) query.set("order", params.order);
  }
  return query.toString();
}

export const inventoryApi = {

  /**
   * Agents in this tenant's scope. Without params the full list comes back (graph views);
   * list pages pass a bounded page plus search, filters and sort, all applied server-side.
   */
  listAgents: (params?: AgentListParams, signal?: AbortSignal) => {
    const qs = params ? agentListQueryString(params) : "";
    return get<AgentsResponse>(`/v1/agents${qs ? `?${qs}` : ""}`, signal ? { signal } : {});
  },


  /** Get detailed view of a single agent */
  getAgentDetail: (name: string) => get<AgentDetailResponse>(`/v1/agents/${encodeURIComponent(name)}`),


  /** Get React Flow lifecycle graph for an agent */
  getAgentLifecycle: (name: string) => get<AgentLifecycleResponse>(`/v1/agents/${encodeURIComponent(name)}/lifecycle`),


  /** MCP registry catalog */
  listRegistry: (params?: RegistryListParams, signal?: AbortSignal) => {
    const query = new URLSearchParams();
    if (params?.limit != null) query.set("limit", String(params.limit));
    if (params?.offset) query.set("offset", String(params.offset));
    if (params?.q?.trim()) query.set("q", params.q.trim());
    for (const value of params?.risk ?? []) query.append("risk", value);
    for (const value of params?.category ?? []) query.append("category", value);
    const qs = query.toString();
    return get<RegistryResponse>(`/v1/registry${qs ? `?${qs}` : ""}`, signal ? { signal } : {});
  },

  getRegistryServer: (id: string) => get<RegistryServer>(`/v1/registry/${id}`),


  /** Canonical Agent BOM manifest for humans and agent callers. */
  getAgentBomManifest: () => get<AgentBomManifestResponse>("/v1/agent-bom/manifest"),
};
