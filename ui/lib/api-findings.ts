import type {
  RemediationItem,
  FindingsResponse,
  FindingTriageRequest,
  FindingTriageDecisionRequest,
  FindingTriageResponse,
  FindingTriageVexResponse,
  TicketingConnectionsResponse,
  TicketsListResponse,
  TicketActionResult,
  TicketCreateBody,
  RiskCampaign,
  RiskCampaignsResponse,
  RiskCampaignUpdate,
  RiskCampaignVerificationRequest,
  RiskCampaignVerificationResult,
  RiskCampaignVerificationQueueResponse,
  RiskCampaignTicketRequest,
  RiskCampaignTicketCreateResult,
  RiskCampaignTicketSyncResult,
} from "./api-types";
import { get, post, put, patch } from "./api-transport";

export const findingsApi = {

  // ── Unified findings ──
  listFindings: (filters?: {
    scanId?: string;
    query?: string;
    severity?: string;
    sort?: string;
    limit?: number;
    offset?: number;
    cursor?: string;
    approximateTotal?: boolean;
    groupOccurrences?: boolean;
    // First-class scope + taxonomy filters (issue #3946). All optional +
    // backward compatible; the server canonicalizes and never rejects them.
    provider?: string;
    account?: string;
    environment?: string;
    domain?: string;
    // Compliance drill-through (epic #4790): a framework section id (e.g. `soc2`
    // / `nist-csf`) and, optionally, a control code that narrows within it.
    framework?: string;
    control?: string;
    owner?: string;
    sla?: "overdue" | "due" | "unassigned";
    reachability?: "reachable" | "unreachable" | "unassessed";
    triage?: "not_affected" | "affected" | "under_investigation" | "untriaged";
    lane?: string;
    findingClass?: "vulnerability" | "misconfiguration" | "secret" | "pii" | "identity" | "unclassified";
    status?: "open" | "resolved" | "all";
    // Known-exploited only, or explicitly everything else. Omit for no filter —
    // `false` is the inverse, not the default.
    kev?: boolean;
    includeFacets?: boolean;
    // Default read-window in days (#4009). Omit for the server default (~90d);
    // pass 0 to widen to all retained history.
    windowDays?: number;
  }) => {
    const params = new URLSearchParams();
    if (filters?.scanId) params.set("scan_id", filters.scanId);
    if (filters?.query) params.set("q", filters.query);
    if (filters?.severity) params.set("severity", filters.severity);
    if (filters?.sort) params.set("sort", filters.sort);
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    if (filters?.cursor) params.set("cursor", filters.cursor);
    if (filters?.approximateTotal) params.set("approximate_total", "true");
    if (filters?.groupOccurrences) params.set("group_occurrences", "true");
    if (filters?.provider) params.set("provider", filters.provider);
    if (filters?.account) params.set("account", filters.account);
    if (filters?.environment) params.set("environment", filters.environment);
    if (filters?.domain) params.set("domain", filters.domain);
    if (filters?.framework) params.set("framework", filters.framework);
    if (filters?.control) params.set("control", filters.control);
    if (filters?.owner) params.set("owner", filters.owner);
    if (filters?.sla) params.set("sla", filters.sla);
    if (filters?.reachability) params.set("reachability", filters.reachability);
    if (filters?.triage) params.set("triage", filters.triage);
    if (filters?.lane) params.set("lane", filters.lane);
    if (filters?.findingClass) params.set("finding_class", filters.findingClass);
    if (filters?.kev != null) params.set("kev", String(filters.kev));
    if (filters?.status) params.set("status", filters.status);
    if (filters?.includeFacets) params.set("include_facets", "true");
    if (filters?.windowDays != null) params.set("window_days", String(filters.windowDays));
    const qs = params.toString();
    return get<FindingsResponse>(`/v1/findings${qs ? `?${qs}` : ""}`);
  },



  // ── Exception requests (separate admin approval required) ──
  createException: (body: { vuln_id: string; package_name: string; reason: string }) =>
    post<{ exception_id: string; status: string }>("/v1/exceptions", body),


  // ── ITSM ticketing (connect-once) ──
  // A connection is created once in the Connections hub; every action below runs
  // through the stored, encrypted connection. No credential is ever sent here.
  listTicketingConnections: () =>
    get<TicketingConnectionsResponse>("/v1/ticketing/connections"),

  createTicket: (body: TicketCreateBody) =>
    post<TicketActionResult>("/v1/ticketing/tickets", body),

  /** List filed tickets, optionally narrowed to one finding by its dedupe key. */
  listTickets: async (findingId?: string): Promise<TicketsListResponse> => {
    const resp = await get<TicketsListResponse>("/v1/ticketing/tickets");
    if (!findingId) return resp;
    const tickets = resp.tickets.filter((t) => t.dedupe_key === findingId);
    return { ...resp, tickets, count: tickets.length };
  },

  syncTicket: (ticketId: string) =>
    post<TicketActionResult>(
      `/v1/ticketing/tickets/${encodeURIComponent(ticketId)}/sync`,
      {},
    ),


  // ── Risk campaigns ──
  // Priorities and modeled risk reduction are authoritative server outputs.
  listRiskCampaigns: (options: { cursor?: string; limit?: number; findingId?: string } = {}) => {
    const params = new URLSearchParams({ limit: String(options.limit ?? 25) });
    if (options.cursor) params.set("cursor", options.cursor);
    if (options.findingId) params.set("finding_id", options.findingId);
    return get<RiskCampaignsResponse>(`/v1/campaigns?${params.toString()}`);
  },

  listRiskCampaignVerificationQueue: (
    options: { cursor?: string | null; limit?: number } = {},
  ) => {
    const params = new URLSearchParams();
    if (options.cursor) params.set("cursor", options.cursor);
    params.set("limit", String(Math.min(100, Math.max(1, options.limit ?? 25))));
    return get<RiskCampaignVerificationQueueResponse>(
      `/v1/campaigns/verification-queue?${params.toString()}`,
    );
  },

  updateRiskCampaign: (campaignId: string, body: RiskCampaignUpdate) =>
    patch<RiskCampaign>(
      `/v1/campaigns/${encodeURIComponent(campaignId)}`,
      body,
    ),

  verifyRiskCampaign: (campaignId: string, body: RiskCampaignVerificationRequest) =>
    post<RiskCampaignVerificationResult>(
      `/v1/campaigns/${encodeURIComponent(campaignId)}/verify`,
      body,
    ),

  createRiskCampaignTickets: (
    campaignId: string,
    body: RiskCampaignTicketRequest,
  ) => {
    const boundedBody = {
      ...body,
      limit: Math.min(25, Math.max(1, body.limit ?? 25)),
    };
    return post<RiskCampaignTicketCreateResult>(
      `/v1/campaigns/${encodeURIComponent(campaignId)}/tickets`,
      boundedBody,
    );
  },

  syncRiskCampaignTickets: (
    campaignId: string,
    options: { cursor?: string | null; limit?: number } = {},
  ) => {
    const params = new URLSearchParams();
    if (options.cursor) params.set("cursor", options.cursor);
    params.set("limit", String(Math.min(25, Math.max(1, options.limit ?? 25))));
    return post<RiskCampaignTicketSyncResult>(
      `/v1/campaigns/${encodeURIComponent(campaignId)}/tickets/sync?${params.toString()}`,
      {},
    );
  },


  // ── False Positive Management ──
  markFalsePositive: (body: {
    vulnerability_id: string;
    package: string;
    reason?: string | undefined;
    marked_by?: string | undefined;
  }) => post<{ id: string; vulnerability_id: string; package: string; status: string }>(
    "/v1/findings/false-positive",
    body,
  ),


  // ── Finding triage and signed VEX ──
  createFindingTriage: (body: FindingTriageRequest) =>
    post<FindingTriageResponse["triage"][number]>("/v1/findings/triage", body),

  listFindingTriage: (filters?: { queueState?: string; decision?: string; limit?: number; offset?: number }) => {
    const params = new URLSearchParams();
    if (filters?.queueState) params.set("queue_state", filters.queueState);
    if (filters?.decision) params.set("decision", filters.decision);
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    const qs = params.toString();
    return get<FindingTriageResponse>(`/v1/findings/triage${qs ? `?${qs}` : ""}`);
  },

  updateFindingTriageDecision: (triageId: string, body: FindingTriageDecisionRequest) =>
    put<FindingTriageResponse["triage"][number]>(`/v1/findings/triage/${encodeURIComponent(triageId)}/decision`, body),

  exportFindingTriageVex: (filters?: {
    assignee?: string;
    package?: string;
    vulnerabilityId?: string;
    serverName?: string;
    scope?: "all" | "current";
    query?: string;
    severity?: string;
    scanId?: string;
    provider?: string;
    account?: string;
    environment?: string;
    domain?: string;
    windowDays?: number;
    status?: string;
    lane?: string;
    findingClass?: string;
    kev?: boolean;
    framework?: string;
    control?: string;
    owner?: string;
    sla?: string;
    reachability?: "reachable" | "unreachable" | "unassessed";
    triage?: "not_affected" | "affected" | "under_investigation" | "untriaged";
  }) => {
    const params = new URLSearchParams();
    if (filters?.assignee) params.set("assignee", filters.assignee);
    if (filters?.package) params.set("package", filters.package);
    if (filters?.vulnerabilityId) params.set("vulnerability_id", filters.vulnerabilityId);
    if (filters?.serverName) params.set("server_name", filters.serverName);
    if (filters?.scope) params.set("scope", filters.scope);
    if (filters?.query) params.set("q", filters.query);
    if (filters?.severity) params.set("severity", filters.severity);
    if (filters?.scanId) params.set("scan_id", filters.scanId);
    if (filters?.provider) params.set("provider", filters.provider);
    if (filters?.account) params.set("account", filters.account);
    if (filters?.environment) params.set("environment", filters.environment);
    if (filters?.domain) params.set("domain", filters.domain);
    if (filters?.windowDays != null) params.set("window_days", String(filters.windowDays));
    if (filters?.status) params.set("status", filters.status);
    if (filters?.lane) params.set("lane", filters.lane);
    if (filters?.findingClass) params.set("finding_class", filters.findingClass);
    if (filters?.kev != null) params.set("kev", String(filters.kev));
    if (filters?.framework) params.set("framework", filters.framework);
    if (filters?.control) params.set("control", filters.control);
    if (filters?.owner) params.set("owner", filters.owner);
    if (filters?.sla) params.set("sla", filters.sla);
    if (filters?.reachability) params.set("reachability", filters.reachability);
    if (filters?.triage) params.set("triage", filters.triage);
    const qs = params.toString();
    return get<FindingTriageVexResponse>(`/v1/findings/triage/vex${qs ? `?${qs}` : ""}`);
  },


  // ── Remediation ──
  getCurrentRemediation: () => get<{
    schema_version: "remediation.current.v1";
    remediation_plan: RemediationItem[];
    source_findings: number;
    truncated: boolean;
    warnings: string[];
    /** The findings read window this plan was built from (same default as /findings). */
    window?: { days: number; label: string; applied: boolean } | null | undefined;
  }>("/v1/findings/remediation"),

  /** Remediation plan for a completed scan.
   *
   * Reads the dedicated endpoint rather than `/v1/scan/{id}`. The whole-job
   * read carried every finding, blast radius, asset and exposure path so the
   * page could use one field: 8.7 MB fetched and parsed for a 41 KB plan on the
   * demo estate. */
  getRemediation: async (jobId: string): Promise<RemediationItem[]> => {
    const response = await get<{ remediation_plan?: RemediationItem[] }>(
      `/v1/scan/${jobId}/remediation`,
    );
    return response.remediation_plan ?? [];
  },
};
