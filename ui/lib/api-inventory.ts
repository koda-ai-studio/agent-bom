import type {
  AgentBomManifestResponse,
  AgentsResponse,
  RegistryServer,
  RegistryResponse,
  AgentDetailResponse,
  AgentLifecycleResponse,
} from "./api-types";
import { get } from "./api-transport";

export const inventoryApi = {

  /** Quick agent discovery (no CVE scan) */
  listAgents: () => get<AgentsResponse>("/v1/agents"),


  /** Get detailed view of a single agent */
  getAgentDetail: (name: string) => get<AgentDetailResponse>(`/v1/agents/${encodeURIComponent(name)}`),


  /** Get React Flow lifecycle graph for an agent */
  getAgentLifecycle: (name: string) => get<AgentLifecycleResponse>(`/v1/agents/${encodeURIComponent(name)}/lifecycle`),


  /** MCP registry catalog */
  listRegistry: () => get<RegistryResponse>("/v1/registry"),

  getRegistryServer: (id: string) => get<RegistryServer>(`/v1/registry/${id}`),


  /** Canonical Agent BOM manifest for humans and agent callers. */
  getAgentBomManifest: () => get<AgentBomManifestResponse>("/v1/agent-bom/manifest"),
};
