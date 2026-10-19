import type { ReportJobRecord, ReportCreateRequest } from "./api-types";
import { get, post, getBlob } from "./api-transport";

export const reportsApi = {

  // ── Operations & Integrations: async reports ──
  /** Enqueue an async findings export (gzipped NDJSON). */
  createReportJob: (body: ReportCreateRequest = {}) =>
    post<ReportJobRecord>("/v1/reports", body),

  /** Poll async report job status and download metadata. */
  getReportJob: (jobId: string) =>
    get<ReportJobRecord>(`/v1/reports/${encodeURIComponent(jobId)}`, { ttlMs: 0 }),

  /** Download a completed report artifact. The job-scoped token is sent via
   *  header (kept out of logs/history), never in the URL. */
  downloadReportArtifact: (jobId: string, token: string) =>
    getBlob(`/v1/reports/${encodeURIComponent(jobId)}/download`, {
      "X-Agent-Bom-Download-Token": token,
    }),
};
