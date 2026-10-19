import type {
  CloudConnectionRecord,
  CloudConnectionsResponse,
  CloudConnectionCreateRequest,
  CloudConnectionUpdateRequest,
  CloudConnectionTestResponse,
  CloudConnectionScanResponse,
} from "./api-types";
import type {
  SideScanProvider,
  SideScanListResponse,
  SideScanExecutionResponse,
  SideScanTriggerRequest,
} from "./api-contracts";
import { get, post, patch, del, mutationIdempotencyKey } from "./api-transport";

export const cloudApi = {

  // ── Cloud connections plane (#3175) ──
  /** List this tenant's read-only cloud connections (non-secret metadata only). */
  listCloudConnections: () => get<CloudConnectionsResponse>("/v1/cloud/connections"),

  /** One connection's non-secret metadata. */
  getCloudConnection: (id: string) =>
    get<CloudConnectionRecord>(`/v1/cloud/connections/${encodeURIComponent(id)}`),

  /**
   * Create a read-only cloud connection. `external_id` is write-only: it is
   * encrypted at rest server-side and never returned in any response.
   */
  createCloudConnection: (body: CloudConnectionCreateRequest) =>
    post<CloudConnectionRecord>("/v1/cloud/connections", body),

  /** Update non-secret connection controls such as recurring scan cadence. */
  updateCloudConnection: (id: string, body: CloudConnectionUpdateRequest) =>
    patch<CloudConnectionRecord>(`/v1/cloud/connections/${encodeURIComponent(id)}`, body),

  /** Delete a connection owned by this tenant. */
  deleteCloudConnection: (id: string) => del(`/v1/cloud/connections/${encodeURIComponent(id)}`),

  /** Validate the stored read-only credential without running inventory/CIS. */
  testCloudConnection: (id: string) =>
    post<CloudConnectionTestResponse>(`/v1/cloud/connections/${encodeURIComponent(id)}/test`, {}),

  /** Queue a durable read-only scan via the credential broker. */
  scanCloudConnection: (id: string) =>
    post<CloudConnectionScanResponse>(
      `/v1/cloud/connections/${encodeURIComponent(id)}/scan`,
      {},
      { "Idempotency-Key": mutationIdempotencyKey("ui-cloud-scan") },
    ),


  // ── CWPP agentless side-scan (Azure/GCP) ──
  /** Recent side-scan executions + honest per-provider executor capabilities. */
  listSideScans: (options?: {
    limit?: number;
    offset?: number;
    provider?: SideScanProvider | undefined;
    status?: string | undefined;
    query?: string | undefined;
  }) => {
    const params = new URLSearchParams();
    params.set("limit", String(options?.limit ?? 50));
    params.set("offset", String(options?.offset ?? 0));
    if (options?.provider) params.set("provider", options.provider);
    if (options?.status) params.set("status", options.status);
    if (options?.query?.trim()) params.set("q", options.query.trim());
    return get<SideScanListResponse>(`/v1/cloud/side-scan?${params.toString()}`, { ttlMs: 0 });
  },

  /** One side-scan execution's durable status + metadata-only evidence. */
  getSideScan: (executionId: string) =>
    get<SideScanExecutionResponse>(`/v1/cloud/side-scan/${encodeURIComponent(executionId)}`, { ttlMs: 0 }),

  /** Trigger one agentless Azure/GCP disk side-scan through the shared executor. */
  triggerSideScan: (body: SideScanTriggerRequest) =>
    post<SideScanExecutionResponse>("/v1/cloud/side-scan", body, {
      "Idempotency-Key": mutationIdempotencyKey("ui-side-scan"),
    }),
};
