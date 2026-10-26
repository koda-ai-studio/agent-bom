import { ApiConflictError, ApiError, ApiNotFoundError, ApiServerError, ApiValidationError } from "./api-errors";
import { findingsApi } from "./api-findings";
import { get } from "./api-transport";

export type AffectedVerdict = "affected" | "possibly_affected" | "not_affected";
export type AffectedVerdictFilter = AffectedVerdict | "all";
export type AffectedProvenance = "operator_advisory" | "feed" | "scan";

export const AFFECTED_VERDICT_FILTERS: readonly AffectedVerdictFilter[] = ["all", "affected", "possibly_affected", "not_affected"];
export const AFFECTED_PAGE_LIMIT = 50;

export interface AdvisoryAffectedRow {
  asset: { agent: string; server: string };
  asset_label: string;
  package: { name: string; version: string; ecosystem: string; purl?: string | undefined; cpe?: string | undefined };
  installed_version: string;
  fixed_version: string | null;
  verdict: AffectedVerdict;
  verdict_reason: string | null;
  verdict_detail: string | null;
  provenance: AffectedProvenance;
  scan_id: string | null;
  last_observed_at: string | null;
  graph: { package_node_id: string; server_node_id: string | null; agent_node_id: string | null };
}

export interface AdvisoryAffectedSummary {
  affected: number;
  possibly_affected: number;
  not_affected: number;
  clean_scanned: number;
  assets_examined: number;
  reports_examined: number;
}

/** `GET /v1/intel/advisories/{id}/affected` — schema `advisory-affected.v1`. */
export interface AdvisoryAffectedResponse {
  schema_version: "advisory-affected.v1";
  tenant_id: string;
  advisory: {
    id: string;
    aliases: string[];
    summary: string;
    severity: string;
    /** `scan`: no declaration or feed record knows the id; answered from the stored findings that name it. */
    source: AffectedProvenance;
    published_at: string | null;
    fixed_versions: string[];
  };
  summary: AdvisoryAffectedSummary;
  complete: boolean;
  /** Why `complete` is false when the cause is the source itself (e.g. answered from stored findings). */
  incomplete_reason?: string | undefined;
  generation: string;
  rows: AdvisoryAffectedRow[];
  count: number;
  limit: number;
  has_more: boolean;
  next_cursor: string | null;
  warnings: string[];
}

export interface AdvisoryAffectedQuery {
  verdict?: AffectedVerdictFilter | undefined;
  limit?: number | undefined;
  cursor?: string | null | undefined;
  q?: string | undefined;
}

export function isAffectedVerdictFilter(value: string | null): value is AffectedVerdictFilter {
  return value !== null && (AFFECTED_VERDICT_FILTERS as readonly string[]).includes(value);
}

export function advisoryAffectedPath(advisoryId: string, query: AdvisoryAffectedQuery = {}): string {
  const params = new URLSearchParams();
  params.set("verdict", query.verdict ?? "all");
  params.set("limit", String(Math.min(200, Math.max(1, query.limit ?? AFFECTED_PAGE_LIMIT))));
  if (query.cursor) params.set("cursor", query.cursor);
  const q = query.q?.trim();
  if (q) params.set("q", q);
  return `/v1/intel/advisories/${encodeURIComponent(advisoryId)}/affected?${params.toString()}`;
}

export function getAdvisoryAffected(advisoryId: string, query: AdvisoryAffectedQuery = {}, signal?: AbortSignal) {
  return get<AdvisoryAffectedResponse>(advisoryAffectedPath(advisoryId, query), { ttlMs: 0, ...(signal ? { signal } : {}) });
}

/** How many findings (`/v1/findings?q=`) name an advisory id the affected route does not know. */
export async function countFindingsReferencing(advisoryId: string, signal?: AbortSignal): Promise<number> {
  if (signal?.aborted) return 0;
  const page = await findingsApi.listFindings({ query: advisoryId, limit: 1 });
  return typeof page.total === "number" && Number.isFinite(page.total) ? page.total : 0;
}

export type AffectedLoadFailure =
  | { kind: "not_found"; message: string }
  | { kind: "snapshot_changed"; message: string }
  | { kind: "invalid"; message: string }
  | { kind: "seeding"; message: string; retryAfterSeconds: number | null }
  | { kind: "error"; message: string };

/** Map the route's documented error statuses to the states the view renders. */
export function classifyAffectedFailure(error: unknown): AffectedLoadFailure {
  const message = error instanceof Error ? error.message : "Request failed";
  if (error instanceof ApiNotFoundError) return { kind: "not_found", message };
  if (error instanceof ApiConflictError) return { kind: "snapshot_changed", message };
  if (error instanceof ApiValidationError) return { kind: "invalid", message };
  if (error instanceof ApiServerError && error.status === 503) {
    return { kind: "seeding", message, retryAfterSeconds: error.retryAfterSeconds ?? null };
  }
  if (error instanceof ApiError && error.status === 404) return { kind: "not_found", message };
  return { kind: "error", message };
}
