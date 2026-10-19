import type {
  GraphSnapshot,
  GraphCorrelationCreate,
  GraphCorrelationList,
  GraphCorrelationRun,
  GraphScenario,
  GraphScenariosResponse,
  GraphScenarioResponse,
  GraphScenarioComparisonResponse,
  GraphHistoryResponse,
  UnifiedGraphResponse,
  FixFirstGraphViewResponse,
  GraphQueryRequest,
  GraphConsequenceRequest,
  GraphConsequenceResponse,
  GraphCompromiseRequest,
  GraphCompromiseResponse,
  GraphQueryResponse,
  GraphNodeDetailResponse,
  GraphNodeNeighborsResponse,
  GraphNeighborDirection,
  GraphImpactResponse,
  NhiGovernancePosture,
  GraphFilterPreset,
  GraphFilterPresetCreate,
  GraphRollupResponse,
  GraphSearchResponse,
  GraphAgentsResponse,
  GraphDiffResponse,
  GraphEstateChangesResponse,
  GraphEdgeChangesResponse,
  InventorySummaryResponse,
  InventorySummaryFilters,
  InventoryAssetsResponse,
  InventoryAssetDetailResponse,
  AttackFlowResponse,
  ContextGraphResponse,
} from "./api-types";
import { ApiError } from "./api-errors";
import type { GraphExposurePathsResponse, GraphDeployDecisionResponse } from "./api-contracts";
import { get, post, put, del, mutationIdempotencyKey } from "./api-transport";

export const graphApi = {

  /** Get attack flow graph for a completed scan */
  getAttackFlow: (
    jobId: string,
    filters?: { cve?: string; severity?: string; framework?: string; agent?: string }
  ) => {
    const params = new URLSearchParams();
    if (filters?.cve) params.set("cve", filters.cve);
    if (filters?.severity) params.set("severity", filters.severity);
    if (filters?.framework) params.set("framework", filters.framework);
    if (filters?.agent) params.set("agent", filters.agent);
    const qs = params.toString();
    return get<AttackFlowResponse>(`/v1/scan/${jobId}/attack-flow${qs ? `?${qs}` : ""}`);
  },


  /** Get context graph with lateral movement analysis */
  getContextGraph: (jobId: string, agent?: string) => {
    const params = new URLSearchParams();
    if (agent) params.set("agent", agent);
    const qs = params.toString();
    return get<ContextGraphResponse>(`/v1/scan/${jobId}/context-graph${qs ? `?${qs}` : ""}`);
  },


  /** List persisted unified graph snapshots */
  getGraphSnapshots: (limit = 50, windowDays?: number, options?: { signal?: AbortSignal }) => {
    const params = new URLSearchParams({ limit: String(limit) });
    // Default read-window (#4009): omit for the server default (~90d); pass 0 to
    // widen to all retained snapshots so old history is never silently hidden.
    if (windowDays != null) params.set("window_days", String(windowDays));
    return get<GraphSnapshot[]>(`/v1/graph/snapshots?${params.toString()}`, options);
  },


  /** Correlate 2-32 exact immutable graph snapshots into one provenance-rich snapshot. */
  createGraphCorrelation: (request: GraphCorrelationCreate) =>
    post<GraphCorrelationRun>("/v1/graph/correlations", request, {
      "Idempotency-Key": mutationIdempotencyKey("graph-correlation"),
    }),


  /** Read one tenant-scoped graph correlation run. */
  getGraphCorrelation: (correlationId: string) =>
    get<GraphCorrelationRun>(`/v1/graph/correlations/${encodeURIComponent(correlationId)}`),


  /** List recent tenant-scoped graph correlation runs. */
  listGraphCorrelations: (limit = 50) =>
    get<GraphCorrelationList>(`/v1/graph/correlations?limit=${limit}`),


  /** List persistent, snapshot-pinned proposed architecture scenarios. */
  getGraphScenarios: () =>
    get<GraphScenariosResponse>("/v1/graph/scenarios"),


  /** Compare one proposed scenario against its exact observed base snapshot. */
  getGraphScenarioComparison: (scenarioId: string, scanId: string) => {
    const params = new URLSearchParams({ scan_id: scanId });
    return get<GraphScenarioComparisonResponse>(
      `/v1/graph/scenarios/${encodeURIComponent(scenarioId)}/comparison?${params.toString()}`,
    );
  },


  /** Persist a new snapshot-pinned proposed architecture scenario. */
  createGraphScenario: (scenario: Omit<GraphScenario, "scenario_id" | "tenant_id" | "revision" | "created_by" | "created_at" | "updated_at">) =>
    post<GraphScenarioResponse>("/v1/graph/scenarios", scenario),


  /** Replace a scenario using optimistic revision control. */
  updateGraphScenario: (
    scenarioId: string,
    scenario: Omit<GraphScenario, "scenario_id" | "tenant_id" | "base_scan_id" | "revision" | "created_by" | "created_at" | "updated_at"> & { expected_revision: number },
  ) =>
    put<GraphScenarioResponse>(
      `/v1/graph/scenarios/${encodeURIComponent(scenarioId)}`,
      { ...scenario, scenario_id: scenarioId },
    ),



  /** Retained graph history with adjacent diff summaries — GET /v1/graph/history */
  getGraphHistory: (limit = 50, windowDays?: number) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (windowDays != null) params.set("window_days", String(windowDays));
    return get<GraphHistoryResponse>(`/v1/graph/history?${params.toString()}`);
  },


  /** Capped node/edge lists for the drift lens; counts come from `summary.totals`. */
  getGraphDiff: (oldScanId: string, newScanId: string) => {
    const params = new URLSearchParams();
    params.set("old", oldScanId);
    params.set("new", newScanId);
    params.set("view", "full");
    return get<GraphDiffResponse>(`/v1/graph/diff?${params.toString()}`);
  },


  /** Per-source changes: each current target scope against its own previous snapshot. */
  getGraphEstateChanges: (options?: { limit?: number; offset?: number; signal?: AbortSignal }) => {
    const params = new URLSearchParams({ limit: String(options?.limit ?? 50) });
    if (options?.offset) params.set("offset", String(options.offset));
    return get<GraphEstateChangesResponse>(`/v1/graph/changes?${params.toString()}`, options?.signal ? { signal: options.signal } : {});
  },


  /** Rich edge lifecycle changes between two snapshots (added/removed/changed). */
  getGraphEdgeChanges: (oldScanId: string, newScanId: string) => {
    const params = new URLSearchParams();
    params.set("old", oldScanId);
    params.set("new", newScanId);
    return get<GraphEdgeChangesResponse>(`/v1/graph/edges/changes?${params.toString()}`);
  },


  /** Load the unified graph for a specific snapshot or the latest persisted state */
  getGraph: (filters?: {
    scanId?: string | undefined;
    entityTypes?: string[] | undefined;
    minSeverity?: string | undefined;
    relationships?: string[] | undefined;
    staticOnly?: boolean | undefined;
    dynamicOnly?: boolean | undefined;
    maxDepth?: number | undefined;
    offset?: number | undefined;
    limit?: number | undefined;
    snapshotGeneration?: string | undefined;
    cursor?: string | undefined;
  }) => {
    const params = new URLSearchParams();
    if (filters?.scanId) params.set("scan_id", filters.scanId);
    if (filters?.entityTypes && filters.entityTypes.length > 0) {
      params.set("entity_types", filters.entityTypes.join(","));
    }
    if (filters?.minSeverity) params.set("min_severity", filters.minSeverity);
    if (filters?.relationships && filters.relationships.length > 0) {
      params.set("relationships", filters.relationships.join(","));
    }
    if (filters?.staticOnly) params.set("static_only", "true");
    if (filters?.dynamicOnly) params.set("dynamic_only", "true");
    if (filters?.maxDepth != null) params.set("max_depth", String(filters.maxDepth));
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    if (filters?.cursor) params.set("cursor", filters.cursor);
    if (filters?.snapshotGeneration) params.set("snapshot_generation", filters.snapshotGeneration);
    const qs = params.toString();
    return get<UnifiedGraphResponse>(`/v1/graph${qs ? `?${qs}` : ""}`);
  },


  /** Read the store-backed, tenant-scoped inventory summary. */
  getInventorySummary: (scanId?: string, filters?: InventorySummaryFilters) => {
    const params = new URLSearchParams();
    if (scanId) params.set("scan_id", scanId);
    if (filters?.type?.length) params.set("type", filters.type.join(","));
    if (filters?.search) params.set("search", filters.search);
    if (filters?.environment) params.set("environment", filters.environment);
    if (filters?.provider) params.set("provider", filters.provider);
    if (filters?.source) params.set("source", filters.source);
    if (filters?.severity) params.set("severity", filters.severity);
    if (filters?.minSeverity) params.set("min_severity", filters.minSeverity);
    const qs = params.toString();
    const url = `/v1/inventory/summary${qs ? `?${qs}` : ""}`;
    return get<InventorySummaryResponse>(url).then((response) => {
      // Older servers ignore unknown query parameters. Never relabel their
      // global aggregate as a filtered result without the resolved scope.
      const echoed = response.filters;
      const mismatch = (scanId && response.scan_id !== scanId) || [...params.entries()].some(([key, value]) => {
        if (key === "scan_id") return false;
        if (!echoed) return true;
        if (key === "type") return value.split(",").map((type) => type.trim()).sort().join(",") !== [...(echoed.type ?? [])].sort().join(",");
        const expected = key === "severity" || key === "min_severity" ? value.trim().toLowerCase() : key === "search" ? value.trim() : value;
        return echoed[key as keyof typeof echoed] !== expected;
      });
      if (mismatch) throw new ApiError("The server could not confirm this inventory scope. Scoped counts are unavailable.", {
        status: 503, statusText: "Scoped summary unavailable", url: "/v1/inventory/summary", method: "GET",
      });
      return response;
    });
  },


  /** Read one bounded, cursor-paged inventory page from the shared store. */
  getInventoryAssets: (filters?: {
    type?: string[] | undefined;
    search?: string | undefined;
    environment?: string | undefined;
    provider?: string | undefined;
    source?: string | undefined;
    severity?: string | undefined;
    minSeverity?: string | undefined;
    scanId?: string | undefined;
    cursor?: string | undefined;
    offset?: number | undefined;
    limit?: number | undefined;
  }) => {
    const params = new URLSearchParams();
    if (filters?.type?.length) params.set("type", filters.type.join(","));
    if (filters?.search) params.set("search", filters.search);
    if (filters?.environment) params.set("environment", filters.environment);
    if (filters?.provider) params.set("provider", filters.provider);
    if (filters?.source) params.set("source", filters.source);
    if (filters?.severity) params.set("severity", filters.severity);
    if (filters?.minSeverity) params.set("min_severity", filters.minSeverity);
    if (filters?.scanId) params.set("scan_id", filters.scanId);
    if (filters?.cursor) params.set("cursor", filters.cursor);
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    const qs = params.toString();
    return get<InventoryAssetsResponse>(`/v1/inventory/assets${qs ? `?${qs}` : ""}`);
  },


  /** Load one bounded, snapshot-pinned page of recorded relationships. */
  getInventoryAsset: (assetId: string, scanId?: string, page?: { cursor?: string; snapshotGeneration?: string; limit?: number }) => {
    const params = new URLSearchParams();
    if (scanId) params.set("scan_id", scanId);
    if (page?.cursor) params.set("cursor", page.cursor);
    if (page?.snapshotGeneration) params.set("snapshot_generation", page.snapshotGeneration);
    if (page?.limit != null) params.set("limit", String(page.limit));
    const qs = params.size ? `?${params.toString()}` : "";
    return get<InventoryAssetDetailResponse>(
      `/v1/inventory/assets/${encodeURIComponent(assetId)}${qs}`,
    );
  },


  /** Load the ranked fix-first security graph view model */
  getFixFirstGraphView: (filters?: {
    scanId?: string | undefined;
    cve?: string | undefined;
    packageName?: string | undefined;
    agentName?: string | undefined;
    limit?: number | undefined;
  }) => {
    const params = new URLSearchParams();
    if (filters?.scanId) params.set("scan_id", filters.scanId);
    if (filters?.cve) params.set("cve", filters.cve);
    if (filters?.packageName) params.set("package", filters.packageName);
    if (filters?.agentName) params.set("agent", filters.agentName);
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    const qs = params.toString();
    return get<FixFirstGraphViewResponse>(`/v1/graph/views/fix-first${qs ? `?${qs}` : ""}`);
  },


  /** Load the global risk-sorted attack path queue without node-page coupling */
  getGraphAttackPaths: (filters?: {
    scanId?: string | undefined;
    snapshotGeneration?: string | undefined;
    offset?: number | undefined;
    limit?: number | undefined;
    /** Server-side focus over the whole ranked queue (a replaced id resolves to its canonical node). */
    nodeId?: string | undefined;
    findingId?: string | undefined;
  }, options?: { signal?: AbortSignal }) => {
    const params = new URLSearchParams();
    if (filters?.scanId) params.set("scan_id", filters.scanId);
    if (filters?.nodeId) params.set("node_id", filters.nodeId);
    if (filters?.findingId) params.set("finding_id", filters.findingId);
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    if (filters?.snapshotGeneration) params.set("snapshot_generation", filters.snapshotGeneration);
    const qs = params.toString();
    return get<UnifiedGraphResponse>(`/v1/graph/attack-paths${qs ? `?${qs}` : ""}`, options);
  },


  /** Ranked ExposurePath queue (agent-native lens) over REST — GET /v1/graph/exposure-paths */
  getGraphExposurePaths: (filters?: {
    scanId?: string | undefined;
    limit?: number | undefined;
    minRisk?: number | undefined;
    cursor?: string | undefined;
  }) => {
    const params = new URLSearchParams();
    if (filters?.scanId) params.set("scan_id", filters.scanId);
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    if (filters?.minRisk != null) params.set("min_risk", String(filters.minRisk));
    if (filters?.cursor) params.set("cursor", filters.cursor);
    const qs = params.toString();
    return get<GraphExposurePathsResponse>(`/v1/graph/exposure-paths${qs ? `?${qs}` : ""}`);
  },


  /** "Should I deploy" gate — POST /v1/graph/should-i-deploy → GO/REVIEW/BLOCK decision */
  graphShouldIDeploy: (body: {
    candidate: string;
    scanId?: string | undefined;
    limit?: number | undefined;
    warnRisk?: number | undefined;
    blockRisk?: number | undefined;
  }) => {
    const payload: Record<string, unknown> = { candidate: body.candidate };
    if (body.scanId) payload.scan_id = body.scanId;
    if (body.limit != null) payload.limit = body.limit;
    if (body.warnRisk != null) payload.warnRisk = body.warnRisk;
    if (body.blockRisk != null) payload.blockRisk = body.blockRisk;
    return post<GraphDeployDecisionResponse>("/v1/graph/should-i-deploy", payload);
  },


  /** Assess explicit control assumptions against one pinned graph revision. */
  assessConsequences: (body: GraphConsequenceRequest, options?: { signal?: AbortSignal }) =>
    post<GraphConsequenceResponse>("/v1/graph/consequences", body, {}, options?.signal),


  assessCompromise: (body: GraphCompromiseRequest, options?: { signal?: AbortSignal }) =>
    post<GraphCompromiseResponse>("/v1/graph/compromise", body, {}, options?.signal),


  /** Run a bounded root-centered graph traversal */
  queryGraph: (body: GraphQueryRequest, options?: { signal?: AbortSignal }) =>
    post<GraphQueryResponse>("/v1/graph/query", body, {}, options?.signal),


  /** Search graph nodes within a snapshot */
  searchGraph: (
    query: string,
    filters?: {
      scanId?: string;
      entityTypes?: string[];
      minSeverity?: string;
      compliancePrefixes?: string[];
      dataSources?: string[];
      offset?: number;
      limit?: number;
      snapshotGeneration?: string | undefined;
      cursor?: string;
    },
  ) => {
    const params = new URLSearchParams();
    params.set("q", query);
    if (filters?.scanId) params.set("scan_id", filters.scanId);
    if (filters?.entityTypes && filters.entityTypes.length > 0) {
      params.set("entity_types", filters.entityTypes.join(","));
    }
    if (filters?.minSeverity) params.set("min_severity", filters.minSeverity);
    if (filters?.compliancePrefixes && filters.compliancePrefixes.length > 0) {
      params.set("compliance_prefixes", filters.compliancePrefixes.join(","));
    }
    if (filters?.dataSources && filters.dataSources.length > 0) {
      params.set("data_sources", filters.dataSources.join(","));
    }
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    if (filters?.cursor) params.set("cursor", filters.cursor);
    if (filters?.snapshotGeneration) params.set("snapshot_generation", filters.snapshotGeneration);
    return get<GraphSearchResponse>(`/v1/graph/search?${params.toString()}`);
  },



  /** List agent nodes for large graph selectors without loading the full graph */
  listGraphAgents: (filters?: { query?: string; scanId?: string; offset?: number; limit?: number; snapshotGeneration?: string | undefined; cursor?: string }, signal?: AbortSignal) => {
    const params = new URLSearchParams();
    if (filters?.query) params.set("q", filters.query);
    if (filters?.scanId) params.set("scan_id", filters.scanId);
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    if (filters?.cursor) params.set("cursor", filters.cursor);
    if (filters?.snapshotGeneration) params.set("snapshot_generation", filters.snapshotGeneration);
    const qs = params.toString();
    return get<GraphAgentsResponse>(`/v1/graph/agents${qs ? `?${qs}` : ""}`, signal ? { signal } : {});
  },


  getGraphIncidentEdges: (nodeId: string, options: { scanId: string; direction: "in" | "out" | "both"; cursor?: string; snapshotGeneration?: string | undefined; signal: AbortSignal }) => {
    const params = new URLSearchParams({ node_id: nodeId, scan_id: options.scanId, direction: options.direction, limit: "24" });
    if (options.cursor) params.set("cursor", options.cursor);
    if (options.snapshotGeneration) params.set("snapshot_generation", options.snapshotGeneration);
    return get<import("./api-types").GraphIncidentPage>(`/v1/graph/incident-edges?${params}`, { signal: options.signal });
  },


  /** Load one graph node plus impact and neighbor context */
  getGraphNode: (nodeId: string, scanId?: string) => {
    const params = new URLSearchParams();
    if (scanId) params.set("scan_id", scanId);
    const queryAddressed = nodeId.includes("/");
    if (queryAddressed) params.set("node_id", nodeId);
    const qs = params.toString();
    const route = queryAddressed ? "/v1/graph/node-context" : `/v1/graph/node/${encodeURIComponent(nodeId)}`;
    return get<GraphNodeDetailResponse>(`${route}${qs ? `?${qs}` : ""}`);
  },


  /** Lazily load a bounded set of one node's direct graph neighbors for inline expand */
  getGraphNodeNeighbors: (
    nodeId: string,
    options?: { scanId?: string | undefined; limit?: number | undefined; direction?: GraphNeighborDirection | undefined },
  ) => {
    const params = new URLSearchParams();
    if (options?.scanId) params.set("scan_id", options.scanId);
    if (options?.limit != null) params.set("limit", String(options.limit));
    if (options?.direction) params.set("direction", options.direction);
    const queryAddressed = nodeId.includes("/");
    if (queryAddressed) params.set("node_id", nodeId);
    const qs = params.toString();
    const route = queryAddressed ? "/v1/graph/node-neighbors" : `/v1/graph/node/${encodeURIComponent(nodeId)}/neighbors`;
    return get<GraphNodeNeighborsResponse>(`${route}${qs ? `?${qs}` : ""}`);
  },


  /** Compute the blast radius (reverse-BFS impact) of a node */
  getGraphImpact: (nodeId: string, scanId?: string, maxDepth?: number, options?: { signal?: AbortSignal }) => {
    const params = new URLSearchParams();
    params.set("node", nodeId);
    if (scanId) params.set("scan_id", scanId);
    if (maxDepth != null) params.set("max_depth", String(maxDepth));
    return get<GraphImpactResponse>(`/v1/graph/impact?${params.toString()}`, options);
  },


  /** NHI governance posture — GET /v1/graph/nhi/governance */
  getNhiGovernance: (scanId?: string) => {
    const params = new URLSearchParams();
    if (scanId) params.set("scan_id", scanId);
    const qs = params.toString();
    return get<NhiGovernancePosture>(`/v1/graph/nhi/governance${qs ? `?${qs}` : ""}`);
  },


  /** List saved graph filter presets — GET /v1/graph/presets */
  listGraphPresets: () => get<GraphFilterPreset[]>("/v1/graph/presets"),


  /** Save a named graph filter preset — POST /v1/graph/presets */
  saveGraphPreset: (body: GraphFilterPresetCreate) =>
    post<{ name: string; status: string }>("/v1/graph/presets", body),


  /** Delete a saved graph filter preset — DELETE /v1/graph/presets/{name} */
  deleteGraphPreset: (name: string) =>
    del(`/v1/graph/presets/${encodeURIComponent(name)}`),


  /** Estate-scale CONTAINS roll-up with optional one-level drill-down */
  getGraphRollup: (
    scanId?: string,
    options?: {
      node?: string;
      minSeverity?: string;
      exposed?: boolean;
      toxic?: boolean;
      mode?: "rollup" | "attack_path";
      /** Top-level or drill-down page; the server defaults to the first 200 entries. */
      offset?: number;
      limit?: number;
      snapshotGeneration?: string | undefined;
    },
  ) => {
    const params = new URLSearchParams();
    if (scanId) params.set("scan_id", scanId);
    if (options?.node) params.set("node", options.node);
    if (options?.minSeverity) params.set("min_severity", options.minSeverity);
    if (options?.exposed) params.set("exposed", "true");
    if (options?.toxic) params.set("toxic", "true");
    if (options?.mode) params.set("mode", options.mode);
    if (options?.offset) params.set("offset", String(options.offset));
    if (options?.limit) params.set("limit", String(options.limit));
    if (options?.snapshotGeneration) params.set("snapshot_generation", options.snapshotGeneration);
    const qs = params.toString();
    return get<GraphRollupResponse>(`/v1/graph/rollup${qs ? `?${qs}` : ""}`);
  },
};
