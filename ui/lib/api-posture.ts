import type {
  PostureCountsResponse,
  TrendsResponse,
  OverviewResponse,
  AccountSummaryResponse,
  ScoreConfigRuntime,
  ScoreConfigUpdate,
  ComplianceNarrativeResponse,
  ComplianceResponse,
  NistCatalogDrill,
  CISBenchmarkChecksResponse,
  FrameworkCatalogsResponse,
  PostureResponse,
  HubPostureResponse,
  EnterpriseDemoStory,
  DemoEstateStatus,
} from "./api-types";
import { get, put, getBlob, DEMO_STORY_TIMEOUT_MS } from "./api-transport";

export const postureApi = {

  /** Full posture grade + dimensions */
  getPosture: () => get<PostureResponse>("/v1/posture"),


  /** Idempotent scan-backed posture history, newest point first. */
  getTrends: (limit = 30, options: { days?: number; scope_id?: string } = {}) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (options.days !== undefined) params.set("days", String(options.days));
    if (options.scope_id) params.set("scope_id", options.scope_id);
    return get<TrendsResponse>(`/v1/trends?${params}`);
  },


  /** Cross-domain posture snapshot for the unified overview landing page */
  getOverview: () => get<OverviewResponse>("/v1/overview"),


  /** Correlated fictional estate, available only when demo-estate mode is enabled. */
  getEnterpriseDemoStory: () => get<EnterpriseDemoStory>("/v1/demo-estate/story", { timeoutMs: DEMO_STORY_TIMEOUT_MS }),


  /** Persisted graph ownership for honest demo-to-graph routing. */
  getDemoEstateStatus: () => get<DemoEstateStatus>("/v1/demo-estate/status"),


  /** Per-account, end-to-end posture drill for one cloud account (#3931) */
  getCloudAccountSummary: (accountRef: string) =>
    get<AccountSummaryResponse>(`/v1/cloud/accounts/${encodeURIComponent(accountRef)}/summary`),



  /** Update the exec risk-score weights, thresholds, or display format (admin) */
  updateScoreConfig: (body: ScoreConfigUpdate) =>
    put<ScoreConfigRuntime>("/v1/overview/score-config", body),



  /** Lightweight aggregate counts + scan context for nav badges */
  getPostureCounts: () => get<PostureCountsResponse>("/v1/posture/counts"),


  /** Compliance posture across all completed scans */
  getCompliance: (scanId?: string) => {
    const params = new URLSearchParams();
    if (scanId?.trim()) params.set("scan_id", scanId.trim());
    const query = params.toString();
    return get<ComplianceResponse>(`/v1/compliance${query ? `?${query}` : ""}`);
  },


  /**
   * Catalog-backed NIST SP 800-53 Rev 5 drill: per-control status, evidencing
   * checks, family rollup, and ISO-27001-by-id attribution. `status` filters the
   * displayed list without changing the counts; `include_not_evaluated`
   * enumerates the full ~1000-control catalog.
   */
  getComplianceNist80053: (opts?: { status?: string; includeNotEvaluated?: boolean }) => {
    const params = new URLSearchParams();
    if (opts?.status) params.set("status", opts.status);
    if (opts?.includeNotEvaluated) params.set("include_not_evaluated", "true");
    const qs = params.toString();
    return get<NistCatalogDrill>(`/v1/compliance/nist-800-53${qs ? `?${qs}` : ""}`);
  },



  /**
   * Tenant-scoped cloud CIS benchmark checks with structured remediation.
   * Server-side filters (cloud/status/priority) are optional; callers that
   * also need a guardrails filter fetch a page and filter client-side.
   */
  listCisBenchmarkChecks: (filters?: {
    cloud?: string;
    status?: string;
    priority?: number;
    limit?: number;
    offset?: number;
  }) => {
    const params = new URLSearchParams();
    if (filters?.cloud) params.set("cloud", filters.cloud);
    if (filters?.status) params.set("status", filters.status);
    if (filters?.priority !== undefined) params.set("priority", String(filters.priority));
    if (filters?.limit !== undefined) params.set("limit", String(filters.limit));
    if (filters?.offset !== undefined) params.set("offset", String(filters.offset));
    const qs = params.toString();
    return get<CISBenchmarkChecksResponse>(`/v1/cis/checks${qs ? `?${qs}` : ""}`);
  },


  /** Active framework catalog metadata surfaced by the API */
  getFrameworkCatalogs: () => get<FrameworkCatalogsResponse>("/v1/frameworks/catalogs"),


  /** Auditor-ready compliance narrative for all tag-mapped frameworks */
  getComplianceNarrative: () => get<ComplianceNarrativeResponse>("/v1/compliance/narrative"),



  /** Compliance Hub: aggregate posture across native + ingested findings (#1044) */
  getHubPosture: () => get<HubPostureResponse>("/v1/compliance/hub/posture"),


  /**
   * Download one signed evidence pack covering every tag-mapped framework.
   * Returns the raw bundle Blob (JSON) so the caller can save it to disk; the
   * tamper-evident signature travels in the response headers.
   */
  downloadCompliancePack: () => getBlob("/v1/compliance/report/pack"),

  /** Signed evidence bundle for one framework (GET /v1/compliance/{framework}/report). */
  getComplianceFrameworkReport: (reportSlug: string) =>
    get<import("./control-evidence").ComplianceReportBundle>(`/v1/compliance/${encodeURIComponent(reportSlug)}/report`),
};
