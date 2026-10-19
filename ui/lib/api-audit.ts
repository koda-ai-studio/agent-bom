import { getSessionAuthHeaders } from "./auth";
import type { AuditLogResponse, AuditIntegrityResponse } from "./api-types";
import type { AuditExportPacket, AuditExportVerifyResult } from "./api-contracts";
import { get, post, _doFetch, withTimeout } from "./api-transport";

export const auditApi = {

  // ── Audit Log ──
  listAuditEntries: (filters?: { action?: string | undefined; resource?: string | undefined; since?: string | undefined; limit?: number | undefined; offset?: number | undefined }) => {
    const params = new URLSearchParams();
    if (filters?.action) params.set("action", filters.action);
    if (filters?.resource) params.set("resource", filters.resource);
    if (filters?.since) params.set("since", filters.since);
    if (filters?.limit) params.set("limit", String(filters.limit));
    if (filters?.offset) params.set("offset", String(filters.offset));
    const qs = params.toString();
    return get<AuditLogResponse>(`/v1/audit${qs ? `?${qs}` : ""}`);
  },

  getAuditIntegrity: (limit = 1000, includeRuntime = true) => get<AuditIntegrityResponse>(`/v1/audit/integrity?limit=${limit}&include_runtime=${includeRuntime}`),


  /**
   * Download a signed audit evidence packet (GET /v1/audit/export). Returns the
   * JSON body together with its detached HMAC signature (response header) so the
   * caller can persist a self-contained, tamper-evident evidence file.
   */
  exportAuditPacket: async (filters?: {
    action?: string | undefined;
    resource?: string | undefined;
    since?: string | undefined;
    limit?: number | undefined;
    offset?: number | undefined;
  }): Promise<AuditExportPacket> => {
    const params = new URLSearchParams();
    params.set("format", "json");
    if (filters?.action) params.set("action", filters.action);
    if (filters?.resource) params.set("resource", filters.resource);
    if (filters?.since) params.set("since", filters.since);
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    const res = await _doFetch(
      `/v1/audit/export?${params.toString()}`,
      { credentials: "include", headers: getSessionAuthHeaders(), signal: withTimeout() },
      "GET",
    );
    const signature = res.headers.get("X-Agent-Bom-Audit-Export-Signature") ?? "";
    const payload = (await res.json()) as unknown;
    return { payload, signature };
  },


  /** Verify a signed audit export packet without returning HMAC key material. */
  verifyAuditPacket: (payload: unknown, signature: string) =>
    post<AuditExportVerifyResult>("/v1/audit/export/verify", { payload, signature }),
};
