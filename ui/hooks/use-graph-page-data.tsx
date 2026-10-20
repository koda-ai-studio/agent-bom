"use client";

import { decodeFiltersFromParams } from "@/lib/filter-algebra";
import { nameScopeCrumbs, type ScopeCrumb } from "@/lib/graph-scope-crumbs";
import { useEffect, useMemo, useRef, useState } from "react";
import { usePathname, useSearchParams } from "next/navigation";
import { useReactFlow, useNodesInitialized, useViewport } from "@xyflow/react";
import { type DriftScrubberPair } from "@/components/graph-drift-timeline";
import { ROLLUP_DECISION_THRESHOLD } from "@/components/graph-rollup-decision-surface";
import { ASSET_DRIFT_GRAPH_SCOPE_PARAM, DEFAULT_FILTERS, createAssetLifecycleDriftGraphFilters, createCanvasLensGraphFilters, graphScopePresetForFilters, type FilterState } from "@/components/lineage-filter";
import { type LineageNodeData } from "@/components/lineage-nodes";
import { type UnifiedNode } from "@/lib/graph-schema";
import { entityTypesForLayers } from "@/lib/graph-entity-mapping";
import { attackPathKey, decodeGraphInvestigationParams, mergeGraphQueueContext, type GraphInvestigationRequest } from "@/lib/attack-paths";
import { type BlastRadiusState } from "@/lib/graph-blast-investigation";
import { type ReachabilitySummary } from "@/lib/graph-reachability";
import { api, ApiRateLimitError, type GraphDiffResponse, type GraphEdgeChangesResponse, type GraphHistorySnapshot, type GraphNodeDetailResponse, type GraphSnapshot, type GraphScenario, type GraphScenarioComparisonResponse, type UnifiedGraphResponse } from "@/lib/api";
import type { GraphRollupResponse } from "@/lib/api-types";
import { mergeReciprocalRollupEdges } from "@/lib/graph-rollup-view";
import { graphRollupCanvasMode, rollupAutoDescendTarget, graphRollupEligible, graphRollupPreferenceForCanvas, parseGraphRollupUrlPreference, parseRollupNodeParam, rollupDismissedForPreference, rollupViewHasContainers } from "@/lib/graph-rollup-default";
import { type DriftLensFilter, type EvidenceLensFilter } from "@/lib/filter-algebra";
import { useCaptureMode } from "@/lib/use-capture-mode";
import { useAuthState } from "@/components/auth-provider";
import { parseGraphScenarioViewState, proposedGraphFromComparison, type GraphScenarioViewState } from "@/lib/graph-scenario";
import { useGraphEstateChanges } from "@/hooks/use-graph-estate-changes";
import { useEstateHighlight } from "@/hooks/use-estate-highlight";
import { resolveScopeAncestry } from "@/lib/graph-scope-ancestry";
import { buildFallbackNodeData, emptyGraphResponse, graphFetchLimitForSnapshot, mergeNodeDetail, RELATIONSHIP_SCOPE_MAP, type InvestigationMode } from "@/lib/graph-page-data";

/** Graph page state and server reads: snapshots, graph pages, scenarios, comparison, roll-up and estate changes. */
export function useGraphPageData() {
  const reactFlow = useReactFlow();
  const nodesInitialized = useNodesInitialized();
  const graphViewport = useViewport();
  const [narrowViewport, setNarrowViewport] = useState(false);
  const [canvasLayoutAspect, setCanvasLayoutAspect] = useState(2.2);
  const [graphNavigationMount, setGraphNavigationMount] = useState<HTMLDivElement | null>(null);
  useEffect(() => {
    const query = window.matchMedia("(max-width: 639px)");
    const update = () => setNarrowViewport(query.matches);
    update();
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);
  const { session, loading: authLoading } = useAuthState();
  const [snapshotRetry, setSnapshotRetry] = useState(0);
  const [snapshotListUnavailable, setSnapshotListUnavailable] = useState(false);
  const [graphRetry, setGraphRetry] = useState(0);
  const [canvasPage, setCanvasPage] = useState(0);
  const [expandedGraphScanId, setExpandedGraphScanId] = useState<string | null>(null);
  const loadedGraphScope = useRef<string | null>(null);
  const [minimapExpanded, setMinimapExpanded] = useState(false);
  const [snapshots, setSnapshots] = useState<GraphSnapshot[]>([]);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [currentEstateId, setCurrentEstateId] = useState("");
  const graphFetchLimit = graphFetchLimitForSnapshot(selectedScanId, expandedGraphScanId);
  const [graphData, setGraphData] = useState<UnifiedGraphResponse | null>(null);
  const [scenarios, setScenarios] = useState<GraphScenario[]>([]);
  const [selectedScenarioId, setSelectedScenarioId] = useState(() =>
    typeof window !== "undefined"
      ? new URLSearchParams(window.location.search).get("scenario") ?? ""
      : "",
  );
  const [expandedScenarioId, setExpandedScenarioId] = useState<string | null>(null);
  const scenarioExpanded = Boolean(selectedScenarioId && expandedScenarioId === selectedScenarioId);
  const [scenarioState, setScenarioState] = useState<GraphScenarioViewState>(() =>
    typeof window !== "undefined"
      ? parseGraphScenarioViewState(
          new URLSearchParams(window.location.search).get("state"),
        )
      : "current",
  );
  const [scenarioComparison, setScenarioComparison] =
    useState<GraphScenarioComparisonResponse | null>(null);
  const [loadingScenarios, setLoadingScenarios] = useState(false);
  const [loadingScenarioComparison, setLoadingScenarioComparison] =
    useState(false);
  const [scenarioError, setScenarioError] = useState<string | null>(null);
  const [scenarioRefreshKey, setScenarioRefreshKey] = useState(0);
  const [attackPathQueue, setAttackPathQueue] = useState<UnifiedGraphResponse | null>(
    null,
  );
  // The scan whose queue request has settled (loaded or failed).
  const [attackPathQueueScanId, setAttackPathQueueScanId] = useState<string | null>(null);
  const [loadingSnapshots, setLoadingSnapshots] = useState(true);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [loadingDiff, setLoadingDiff] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rateLimited, setRateLimited] = useState(false);
  const [diffError, setDiffError] = useState<string | null>(null);
  const [comparisonRequested, setComparisonRequested] = useState(false);
  const [selectedNodeDetail, setSelectedNodeDetail] = useState<{ scanId: string; response: GraphNodeDetailResponse } | null>(null);
  const [graphDiff, setGraphDiff] = useState<GraphDiffResponse | null>(null);
  const [edgeChanges, setEdgeChanges] = useState<GraphEdgeChangesResponse | null>(
    null,
  );
  const [loadingEdgeChanges, setLoadingEdgeChanges] = useState(false);
  const [edgeChangesError, setEdgeChangesError] = useState<string | null>(null);
  const [historySnapshots, setHistorySnapshots] = useState<GraphHistorySnapshot[]>(
    [],
  );
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [driftScrubberPair, setDriftScrubberPair] =
    useState<DriftScrubberPair | null>(null);
  const [driftLensActive, setDriftLensActive] = useState(false);
  const [driftFilter, setDriftFilter] = useState<DriftLensFilter>("all");
  const [changesOpen, setChangesOpen] = useState(false);
  const [evidenceLensActive, setEvidenceLensActive] = useState(false);
  const [evidenceFilter, setEvidenceFilter] =
    useState<EvidenceLensFilter>("all");
  const [selectedNode, setSelectedNode] = useState<LineageNodeData | null>(
    null,
  );
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedRelationship, setSelectedRelationship] = useState<{ scanId: string; id: string } | null>(null);
  const [selectedAttackPathKey, setSelectedAttackPathKey] = useState<
    string | null
  >(null);
  const requestedAttackPathKeyRef = useRef<string | null>(
    typeof window !== "undefined"
      ? new URLSearchParams(window.location.search).get("path")
      : null,
  );
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<UnifiedNode[]>([]);
  const [searching, setSearching] = useState(false);
  const [investigationMode, setInvestigationMode] =
    useState<InvestigationMode | null>(null);
  const [reachabilitySummary, setReachabilitySummary] =
    useState<ReachabilitySummary | null>(null);
  const loadingReachability = false;
  const quietRootRef = useRef<string | null>(null);
  const [mobileGraphView, setMobileGraphView] = useState<"list" | "graph">("list");
  const investigationRequestId = useRef(0);
  const investigationAbort = useRef<AbortController | null>(null);
  useEffect(() => () => investigationAbort.current?.abort(), []);
  const [investigationDirection, setInvestigationDirection] = useState<"forward" | "reverse" | "both">("both");
  const [reachabilityError, setReachabilityError] = useState<string | null>(
    null,
  );
  const [blastRadius, setBlastRadius] = useState<BlastRadiusState | null>(null);
  const [loadingBlast, setLoadingBlast] = useState(false);
  const [blastError, setBlastError] = useState<string | null>(null);
  const [rollupView, setRollupView] = useState<GraphRollupResponse | null>(null);
  const [rollupStack, setRollupStack] = useState<ScopeCrumb[]>(() => {
    if (typeof window === "undefined") return [];
    const nodeId = parseRollupNodeParam(new URLSearchParams(window.location.search));
    return nodeId ? [{ id: nodeId, label: nodeId }] : [];
  });
  const rollupAutoDescendRef = useRef(true);
  const [rollupDismissed, setRollupDismissed] = useState(
    () =>
      typeof window !== "undefined" &&
      parseGraphRollupUrlPreference(
        new URLSearchParams(window.location.search),
      ) === "off",
  );
  const [loadingRollup, setLoadingRollup] = useState(false);
  // Keyed to the drill scope so a new node or filter always starts at page one.
  const [rollupChildPage, setRollupChildPage] = useState<{ key: string; offset: number; generation: string | undefined } | null>(null);
  const [rollupError, setRollupError] = useState<string | null>(null);
  const [rollupUnavailable, setRollupUnavailable] = useState(false);
  const [rollupMapExpanded, setRollupMapExpanded] = useState(false);
  const [rollupSummaryRequested, setRollupSummaryRequested] = useState(false);
  const restoreSummaryOnFilterReset = useRef(false);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [pinnedFocusId, setPinnedFocusId] = useState<string | null>(null);
  const [expandedClusterIds, setExpandedClusterIds] = useState<Set<string>>(
    () => new Set(),
  );
  const pathname = usePathname();
  const searchParams = useSearchParams();
  // Seed filters from URL on first render so /graph?agent=...&severity=high
  // reproduces the exact view in another tab.
  const [filters, setFilters] = useState<FilterState>(() => {
    if (typeof window === "undefined") return DEFAULT_FILTERS;
    const params = new URLSearchParams(window.location.search);
    const initialLens = params.get("lens") ??
      (window.location.pathname.startsWith("/security-graph") ? "estate" : null);
    const baseline = createCanvasLensGraphFilters(
      initialLens,
      params.get("agent"),
    ) ?? (params.get("scope") === ASSET_DRIFT_GRAPH_SCOPE_PARAM
      ? createAssetLifecycleDriftGraphFilters(params.get("agent"))
      : DEFAULT_FILTERS);
    return { ...baseline, ...decodeFiltersFromParams(params) };
  });
  const [initializedFocus, setInitializedFocus] = useState(false);
  // Track whether we've already seeded filters from the URL so the
  // auto-focus effect that picks the first agent doesn't clobber an
  // explicit ?agent= param on initial load.
  const seededFromUrlRef = useRef<boolean>(
    typeof window !== "undefined" &&
      new URLSearchParams(window.location.search).toString().length > 0,
  );
  const requestedScanIdRef = useRef<string>(
    typeof window !== "undefined"
      ? new URLSearchParams(window.location.search).get("scan") ||
          new URLSearchParams(window.location.search).get("scan_id") ||
          ""
      : "",
  );
  // The destination route is available before App Router commits browser
  // history. Reading window here can lose an Identity/Inventory drill-in.
  const requestedInvestigationRef = useRef<GraphInvestigationRequest | null>(
    decodeGraphInvestigationParams(searchParams),
  );
  const rollupPreferenceRef = useRef(
    typeof window !== "undefined"
      ? (() => {
          const params = new URLSearchParams(window.location.search);
          const estateEntry =
            window.location.pathname.startsWith("/security-graph") &&
            (!params.get("lens") || params.get("lens") === "estate");
          return graphRollupPreferenceForCanvas(params, estateEntry);
        })()
      : ("default" as const),
  );
  const explicitCanvasLens = searchParams.get("lens");
  const canvasLens =
    (explicitCanvasLens === "mesh" || explicitCanvasLens === "context" || explicitCanvasLens === "lineage" ? "estate" : explicitCanvasLens) ??
    (pathname?.startsWith("/security-graph") ? "estate" : null);
  // Client-side lens navigation can mount this page before
  // `window.location.search` reflects the destination URL. Reconcile from
  // Next's route state before the later URL-sync effect runs so an explicit
  // `rollup=1` cannot be silently deleted on entry.
  useEffect(() => {
    const preference = graphRollupPreferenceForCanvas(
      searchParams,
      canvasLens === "estate",
    );
    rollupPreferenceRef.current = preference;
    setRollupDismissed(rollupDismissedForPreference(preference));
    const requestedScanId =
      searchParams.get("scan") || searchParams.get("scan_id") || "";
    if (requestedScanId) {
      requestedScanIdRef.current = requestedScanId;
    }
  }, [canvasLens, searchParams]);
  const canvasAgent = searchParams.get("agent");
  const hasRequestedInvestigation = decodeGraphInvestigationParams(searchParams) !== null;
  const canvasLensRef = useRef(canvasLens);
  const canvasAgentRef = useRef(canvasAgent);
  canvasLensRef.current = canvasLens;
  canvasAgentRef.current = canvasAgent;

  const selectedScenario = useMemo(
    () =>
      scenarios.find((scenario) => scenario.scenario_id === selectedScenarioId) ??
      scenarioComparison?.scenario ??
      null,
    [scenarioComparison?.scenario, scenarios, selectedScenarioId],
  );
  const attackPathLens = canvasLens === "attack-path";

  useEffect(() => {
    setLoadingScenarios(true);
    api
      .getGraphScenarios()
      .then((response) => {
        setScenarios(response.scenarios);
        setScenarioError(null);
      })
      .catch(() => {
        // Scenarios are additive. An older/read-only API must not prevent the
        // observed graph from rendering.
        setScenarios([]);
      })
      .finally(() => setLoadingScenarios(false));
  }, []);

  useEffect(() => {
    if (!selectedScenarioId || !selectedScanId) {
      setScenarioComparison(null);
      setScenarioError(null);
      return;
    }
    let cancelled = false;
    setLoadingScenarioComparison(true);
    setScenarioError(null);
    api
      .getGraphScenarioComparison(selectedScenarioId, selectedScanId)
      .then((response) => {
        if (!cancelled) setScenarioComparison(response);
      })
      .catch(() => {
        if (cancelled) return;
        setScenarioComparison(null);
        setScenarioError("Could not load the scenario comparison.");
        setScenarioState("current");
      })
      .finally(() => {
        if (!cancelled) setLoadingScenarioComparison(false);
      });
    return () => {
      cancelled = true;
    };
  }, [scenarioRefreshKey, selectedScanId, selectedScenarioId]);

  useEffect(() => {
    if (attackPathLens && scenarioState !== "current") {
      setScenarioState("current");
    }
  }, [attackPathLens, scenarioState]);

  useEffect(() => {
    const next = createCanvasLensGraphFilters(canvasLens, canvasAgent);
    if (!next || requestedInvestigationRef.current || hasRequestedInvestigation) return;
    setInvestigationMode(null);
    setReachabilitySummary(null);
    setReachabilityError(null);
    setFilters(next);
  }, [canvasAgent, canvasLens, hasRequestedInvestigation]);
  const firstScanSelectionRef = useRef(true);
  // Last URL the filter→URL sync effect wrote, used to break an infinite
  // router.replace loop (see the sync effect below for the full rationale).
  const lastSyncedUrlRef = useRef<string | null>(null);
  const initialContextViewRef = useRef(searchParams.get("context_view") ?? (searchParams.has("layers") ? "all" : null));
  const captureModeFromLocation = useCaptureMode();
  const captureMode = captureModeFromLocation || searchParams.get("capture") === "1";

  useEffect(() => {
    let cancelled = false;
    const requested = requestedScanIdRef.current;
    const namedSnapshot = requested && !requested.startsWith("current-estate:");
    if (namedSnapshot) setSelectedScanId(requested);
    setLoadingSnapshots(true);
    setSnapshotListUnavailable(false);
    void Promise.allSettled([api.getGraphSnapshots(40, 0), !namedSnapshot ? api.getInventorySummary() : Promise.resolve(null)])
      .then(([saved, inventory]) => {
        if (cancelled) return;
        if (saved.status === "fulfilled") setSnapshots(saved.value);
        else setSnapshotListUnavailable(true);
        const currentScope = inventory.status === "fulfilled" ? inventory.value : null;
        setCurrentEstateId(currentScope?.scan_id ?? "");
        if (namedSnapshot || currentScope?.scan_id) {
          setSelectedScanId(current => current || requested || currentScope?.scan_id || "");
          return;
        }
        const failure = inventory.status === "rejected" ? inventory.reason : saved.status === "rejected" ? saved.reason : null;
        if (failure) { setRateLimited(failure instanceof ApiRateLimitError); setError("Graph scope could not be loaded."); }
      })
      .finally(() => { if (!cancelled) setLoadingSnapshots(false); });
    return () => { cancelled = true; };
  }, [snapshotRetry]);

  // External root/scan navigation must invalidate the prior investigation. Native
  // history writes made below are already reflected in state and need no reload.
  useEffect(() => {
    const destination = `${pathname}${searchParams.size ? `?${searchParams}` : ""}`;
    if (destination === lastSyncedUrlRef.current) return;
    const requested = decodeGraphInvestigationParams(searchParams);
    const scan = searchParams.get("scan") || searchParams.get("scan_id") || "";
    if (scan && scan !== selectedScanId) {
      requestedScanIdRef.current = scan;
      setSelectedScanId(scan);
    }
    if (requested && (requested.rootId !== investigationMode?.rootId || (scan && scan !== selectedScanId))) {
      requestedInvestigationRef.current = requested;
    }
  }, [pathname, searchParams, selectedScanId, investigationMode?.rootId]);

  const serverEntityTypes = useMemo(
    () => entityTypesForLayers(filters.layers),
    [filters.layers],
  );

  const serverRelationships = useMemo(
    () => RELATIONSHIP_SCOPE_MAP[filters.relationshipScope],
    [filters.relationshipScope],
  );

  const serverFilterKey = useMemo(
    () =>
      JSON.stringify({
        scanId: selectedScanId,
        entityTypes: serverEntityTypes,
        relationships: serverRelationships,
        runtimeMode: filters.runtimeMode,
        maxDepth: filters.maxDepth,
        severity: filters.severity,
      }),
    [selectedScanId, serverEntityTypes, serverRelationships, filters],
  );

  useEffect(() => {
    setExpandedClusterIds(new Set());
    setCanvasPage(0);
    setPinnedFocusId(null);
    setHoveredNodeId(null);
    setReachabilitySummary(null);
    setReachabilityError(null);
  }, [serverFilterKey]);

  useEffect(() => {
    if (!selectedScanId) return;
    investigationRequestId.current++;
    investigationAbort.current?.abort();
    setLoadingBlast(false);
    setBlastRadius(null);
    setSearchResults([]);
    setSearchQuery("");
    setSelectedAttackPathKey(null);
    setInvestigationMode(null);
    setReachabilitySummary(null);
    setReachabilityError(null);
    setRollupView(null);
    if (!firstScanSelectionRef.current) setRollupStack([]);
    restoreSummaryOnFilterReset.current = false;
    rollupAutoDescendRef.current = true;
    setRollupDismissed(
      rollupDismissedForPreference(rollupPreferenceRef.current),
    );
    setRollupError(null);
    setRollupUnavailable(false);
    if (firstScanSelectionRef.current) {
      firstScanSelectionRef.current = false;
      if (seededFromUrlRef.current) {
        setInitializedFocus(true);
        return;
      }
    }
    setFilters(
      createCanvasLensGraphFilters(
        canvasLensRef.current,
        canvasAgentRef.current,
      ) ??
        DEFAULT_FILTERS,
    );
    setInitializedFocus(false);
  }, [selectedScanId]);

  useEffect(() => {
    if (!selectedScanId) {
      setGraphData(null);
      return;
    }

    if (investigationMode || requestedInvestigationRef.current) return;

    if (serverEntityTypes.length === 0) {
      setGraphData(emptyGraphResponse(selectedScanId));
      setSelectedNode(null);
      setError(null);
      return;
    }

    let cancelled = false;
    if (loadedGraphScope.current !== serverFilterKey) {
      setGraphData(null);
      setSelectedNode(null);
    }
    setLoadingGraph(true);
    api
      .getGraph({
        scanId: selectedScanId,
        entityTypes: serverEntityTypes,
        minSeverity: filters.severity ?? undefined,
        relationships: serverRelationships,
        staticOnly: filters.runtimeMode === "static",
        dynamicOnly: filters.runtimeMode === "dynamic",
        maxDepth: filters.maxDepth,
        // Larger selections are opt-in; preserve the server completeness fields.
        offset: 0,
        limit: graphFetchLimit,
        view: "canvas",
      })
      .then((result) => {
        if (cancelled) return;
        loadedGraphScope.current = serverFilterKey;
        setGraphData(result);
        setError(null);
      })
      .catch((e) => {
        if (cancelled) return;
        setError(e.message);
      })
      .finally(() => {
        if (!cancelled) setLoadingGraph(false);
      });
    return () => {
      cancelled = true;
    };
  }, [
    selectedScanId,
    serverEntityTypes,
    serverRelationships,
    filters.runtimeMode,
    filters.maxDepth,
    filters.severity,
    investigationMode,
    graphRetry,
    graphFetchLimit,
    serverFilterKey,
  ]);

  useEffect(() => {
    if (!selectedScanId) {
      setAttackPathQueue(null);
      return;
    }
    let cancelled = false;
    api
      .getGraphAttackPaths({ scanId: selectedScanId, limit: 75 })
      .then((result) => {
        if (!cancelled) setAttackPathQueue(result);
      })
      .catch(() => {
        if (!cancelled) setAttackPathQueue(null);
      })
      .finally(() => {
        if (!cancelled) setAttackPathQueueScanId(selectedScanId);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedScanId]);

  const mergedGraphData = useMemo(() => {
    return graphData ? mergeGraphQueueContext(graphData, attackPathQueue, Boolean(investigationMode), Boolean(selectedAttackPathKey)) : null;
  }, [attackPathQueue, graphData, investigationMode, selectedAttackPathKey]);

  const proposedGraphData = useMemo(
    () =>
      mergedGraphData
        ? proposedGraphFromComparison(mergedGraphData, scenarioComparison)
        : null,
    [mergedGraphData, scenarioComparison],
  );
  const projectedGraphData =
    scenarioState === "current" || attackPathLens
      ? mergedGraphData
      : proposedGraphData;

  const activeSnapshot = useMemo(
    () =>
      snapshots.find((snapshot) => snapshot.scan_id === selectedScanId) ?? null,
    [snapshots, selectedScanId],
  );
  const previousSnapshot = useMemo(() => {
    const index = snapshots.findIndex(
      (snapshot) => snapshot.scan_id === selectedScanId,
    );
    if (index < 0 || index + 1 >= snapshots.length) return null;
    return snapshots[index + 1];
  }, [snapshots, selectedScanId]);

  const diffPair = useMemo(() => {
    if (driftScrubberPair) return driftScrubberPair;
    if (previousSnapshot && selectedScanId) {
      return {
        oldScanId: previousSnapshot.scan_id,
        newScanId: selectedScanId,
      } satisfies DriftScrubberPair;
    }
    return null;
  }, [driftScrubberPair, previousSnapshot, selectedScanId]);

  const viewingCurrentEstate = selectedScanId.startsWith("current-estate:");
  const graphChanges = useGraphEstateChanges({ scanId: selectedScanId, enabled: viewingCurrentEstate, ready: Boolean(graphData) });
  const highlight = useEstateHighlight({ scanId: selectedScanId, currentEstate: viewingCurrentEstate, estateChanges: graphChanges.estateChanges,
    setPair: setDriftScrubberPair, setLensActive: setDriftLensActive, setPanelOpen: setChangesOpen });

  const needsComparison = comparisonRequested || driftLensActive || Boolean(driftScrubberPair) || graphScopePresetForFilters(filters) === "assetDrift";

  useEffect(() => {
    let cancelled = false;
    setGraphDiff(null);
    setDiffError(null);
    setEdgeChanges(null);
    setEdgeChangesError(null);
    if (!diffPair || !needsComparison) {
      setLoadingDiff(false);
      setLoadingEdgeChanges(false);
      return;
    }
    setLoadingDiff(true);
    setLoadingEdgeChanges(true);
    Promise.all([
      api.getGraphDiff(diffPair.oldScanId, diffPair.newScanId),
      api.getGraphEdgeChanges(diffPair.oldScanId, diffPair.newScanId),
    ])
      .then(([diffResult, edgeResult]) => {
        if (cancelled) return;
        setGraphDiff(diffResult);
        setEdgeChanges(edgeResult);
      })
      .catch((e: Error) => {
        if (cancelled) return;
        setDiffError(e.message);
        setEdgeChangesError(e.message);
      })
      .finally(() => {
        if (!cancelled) {
          setLoadingDiff(false);
          setLoadingEdgeChanges(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [diffPair, needsComparison]);

  useEffect(() => {
    setSelectedNodeDetail(null);
    if (!selectedNodeId || !selectedScanId) return;
    let cancelled = false;
    api
      .getGraphNode(selectedNodeId, selectedScanId)
      .then((detail) => {
        if (cancelled) return;
        setSelectedNodeDetail({ scanId: selectedScanId, response: detail });
        setSelectedNode((current) => {
          const currentId = current?.attributes?.node_id;
          if (currentId && currentId !== selectedNodeId) return current;
          // An investigation root is highlighted, not opened; explicit selections open.
          if (!current) return quietRootRef.current === selectedNodeId ? null : buildFallbackNodeData(detail.node);
          return mergeNodeDetail(current, detail);
        });
      })
      .catch(() => {
        // Keep the lightweight node view if enrichment fails.
      });

    return () => {
      cancelled = true;
    };
  }, [selectedNodeId, selectedScanId]);

  const graphNodeById = useMemo(
    () => new Map((mergedGraphData?.nodes ?? []).map((node) => [node.id, node])),
    [mergedGraphData?.nodes],
  );
  const activeScopePreset = graphScopePresetForFilters(filters);

  useEffect(() => {
    if (activeScopePreset !== "assetDrift") return;
    let cancelled = false;
    setLoadingHistory(true);
    api
      .getGraphHistory(50, 0)
      .then((history) => {
        if (cancelled) return;
        setHistorySnapshots(history.snapshots ?? []);
      })
      .catch(() => {
        if (cancelled) return;
        setHistorySnapshots([]);
      })
      .finally(() => {
        if (!cancelled) setLoadingHistory(false);
      });
    return () => {
      cancelled = true;
    };
  }, [activeScopePreset]);

  const attackPaths = useMemo(
    () =>
      [...(mergedGraphData?.attack_paths ?? [])].sort(
        (left, right) =>
          right.composite_risk - left.composite_risk ||
          right.hops.length - left.hops.length,
      ),
    [mergedGraphData?.attack_paths],
  );

  // Attack-path focus is opt-in (#3932). Auto-selecting the top-ranked path on
  // load filtered the canvas down to a single chain, and when that chain's
  // nodes fell outside the current page/scope the graph rendered the "No nodes
  // match" empty state on top of a fully-populated snapshot. The graph now
  // lands on the full filtered topology; selecting a path from the queue
  // narrows to it.
  const effectiveSelectedAttackPathKey = selectedAttackPathKey;

  const selectedAttackPath = useMemo(
    () =>
      effectiveSelectedAttackPathKey
        ? (attackPaths.find(
            (path) => attackPathKey(path) === effectiveSelectedAttackPathKey,
          ) ?? null)
        : null,
    [attackPaths, effectiveSelectedAttackPathKey],
  );

  useEffect(() => {
    const requested = requestedAttackPathKeyRef.current;
    if (!requested || selectedAttackPathKey || attackPaths.length === 0) return;
    const match = requested === "top"
      ? attackPaths[0]
      : attackPaths.find((path) => attackPathKey(path) === requested);
    if (match) {
      const key = attackPathKey(match);
      requestedAttackPathKeyRef.current = key;
      setSelectedAttackPathKey(key);
    }
  }, [attackPaths, selectedAttackPathKey]);

  useEffect(() => {
    if (!selectedAttackPathKey) return;
    if (
      !attackPaths.some((path) => attackPathKey(path) === selectedAttackPathKey)
    ) {
      setSelectedAttackPathKey(null);
    }
  }, [attackPaths, selectedAttackPathKey]);

  // Prefer the pre-truncation estate total: a bounded load leaves
  // `summary.total_nodes` at what survived the budget, which reads as the whole
  // estate and understates it.
  const estateNodeCount =
    activeSnapshot?.node_count ??
    rollupView?.summary.total_nodes_source ??
    rollupView?.summary.total_nodes ??
    graphData?.nodes.length ??
    0;

  const rollupEligible = scenarioState === "current" && graphRollupEligible({
    hasSelectedScan: Boolean(selectedScanId),
    rollupPreference: rollupPreferenceRef.current,
    rollupDismissed,
    estateNodeCount,
    investigationMode: Boolean(investigationMode),
    selectedAttackPath: Boolean(selectedAttackPath),
    reachabilityActive: Boolean(reachabilitySummary),
    blastRadiusActive: Boolean(blastRadius),
    attackPathCount: attackPaths.length,
  });

  const rollupCanvasMode = graphRollupCanvasMode({
    eligible: rollupEligible,
    dismissed: rollupDismissed,
    hasView: rollupView !== null,
    unavailable: rollupUnavailable,
    failed: rollupError !== null,
  });
  const rollupNavigationActive = rollupCanvasMode === "active";
  const rollupCanvasPending = rollupCanvasMode === "loading";
  const rollupCanvasFailed = rollupCanvasMode === "failed";
  const rollupCanvasOwnsPresentation =
    rollupNavigationActive || rollupCanvasPending || rollupCanvasFailed;
  const rollupItems = useMemo(
    () =>
      rollupView?.mode === "drilldown"
        ? (rollupView.children ?? [])
        : (rollupView?.top_level ?? []),
    [rollupView],
  );
  const rollupDecisionAvailable =
    rollupNavigationActive && (rollupItems.length > ROLLUP_DECISION_THRESHOLD || rollupSummaryRequested);
  const rollupDecisionActive = rollupDecisionAvailable && !rollupMapExpanded;

  useEffect(() => {
    setRollupMapExpanded(false);
  }, [rollupView?.mode, rollupView?.node?.id]);

  const rollupChildPageKey = `${selectedScanId ?? ""}\u0000${rollupStack.at(-1)?.id ?? ""}\u0000${filters.severity ?? ""}`;

  useEffect(() => {
    if (!selectedScanId || !rollupEligible || rollupDismissed) {
      return;
    }

    let cancelled = false;
    setLoadingRollup(true);
    setRollupError(null);
    setRollupUnavailable(false);
    const drillNode = rollupStack.at(-1)?.id;
    const childOffset = rollupChildPage?.key === rollupChildPageKey ? rollupChildPage.offset : 0;

    api
      .getGraphRollup(selectedScanId, {
        limit: 100,
        ...(drillNode ? { node: drillNode } : {}),
        ...(filters.severity ? { minSeverity: filters.severity } : {}),
        ...(childOffset ? { offset: childOffset, snapshotGeneration: rollupChildPage?.generation } : {}),
      })
      .then((result) => {
        if (cancelled) return;
        if (
          !rollupViewHasContainers(
            result.mode,
            result.top_level,
            result.children,
          )
        ) {
          setRollupView(null);
          setRollupUnavailable(true);
          setRollupError(null);
          return;
        }
        const autoDescend = childOffset
          ? null
          : rollupAutoDescendTarget(result, {
              stack: rollupStack,
              allowed: rollupAutoDescendRef.current,
            });
        if (autoDescend) {
          setRollupStack((current) =>
            current.at(-1)?.id === autoDescend.id ? current : [...current, autoDescend],
          );
          return;
        }
        setRollupView(result);
        // A deep-linked scope only knows its id until the server names it.
        const named = result.node;
        setRollupStack(current => nameScopeCrumbs(current, named));
        setRollupUnavailable(false);
        setRollupError(null);
      })
      .catch((e) => {
        if (cancelled) return;
        setRollupError(e.message);
        setRollupView(null);
        setRollupUnavailable(false);
      })
      .finally(() => {
        if (!cancelled) setLoadingRollup(false);
      });

    return () => {
      cancelled = true;
    };
  }, [
    selectedScanId,
    rollupEligible,
    rollupDismissed,
    rollupStack,
    filters.severity,
    graphRetry,
    rollupChildPage,
    rollupChildPageKey,
  ]);

  // A deep-linked scope arrives as one crumb; resolve its recorded containment
  // ancestors once so the breadcrumb reads All scopes > org > account > scope.
  const ancestryResolvedFor = useRef<string | null>(null);
  const soleScopeId = rollupStack.length === 1 ? rollupStack[0]!.id : null;
  useEffect(() => {
    if (!selectedScanId || !soleScopeId || ancestryResolvedFor.current === `${selectedScanId}:${soleScopeId}`) return;
    ancestryResolvedFor.current = `${selectedScanId}:${soleScopeId}`;
    let cancelled = false;
    void resolveScopeAncestry(api.getGraphNode, soleScopeId, selectedScanId).then(ancestors => {
      if (cancelled || ancestors.length === 0) return;
      setRollupStack(current => current.length === 1 && current[0]?.id === soleScopeId ? [...ancestors, ...current] : current);
    });
    return () => { cancelled = true; };
  }, [soleScopeId, selectedScanId]);

  // The root roll-up carries the estate's issue basis; drill-downs do not.
  const [estateIssues, setEstateIssues] = useState<{ scanId: string; issue_count?: number | undefined; finding_occurrence_count?: number | undefined } | null>(null);
  useEffect(() => {
    const summary = rollupView?.summary;
    if (rollupView && typeof summary?.issue_count === "number") {
      setEstateIssues({ scanId: rollupView.scan_id, issue_count: summary.issue_count, finding_occurrence_count: summary.finding_occurrence_count });
    }
  }, [rollupView]);
  const estateIssueSummary = estateIssues?.scanId && rollupView && estateIssues.scanId !== rollupView.scan_id ? null : estateIssues;

  const rollupDisplayEdges = useMemo(() => mergeReciprocalRollupEdges(rollupView?.edges ?? []), [rollupView?.edges]);

  return {
    reactFlow, nodesInitialized, graphViewport, narrowViewport, setNarrowViewport, canvasLayoutAspect,
    setCanvasLayoutAspect, graphNavigationMount, setGraphNavigationMount, session, authLoading, snapshotRetry,
    setSnapshotRetry, snapshotListUnavailable, setSnapshotListUnavailable, graphRetry, setGraphRetry, canvasPage,
    setCanvasPage, expandedGraphScanId, setExpandedGraphScanId, loadedGraphScope, minimapExpanded, setMinimapExpanded,
    snapshots, setSnapshots, selectedScanId, setSelectedScanId, currentEstateId, setCurrentEstateId, graphFetchLimit,
    graphData, setGraphData, scenarios, setScenarios, selectedScenarioId, setSelectedScenarioId, expandedScenarioId,
    setExpandedScenarioId, scenarioExpanded, scenarioState, setScenarioState, scenarioComparison,
    setScenarioComparison, loadingScenarios, setLoadingScenarios, loadingScenarioComparison,
    setLoadingScenarioComparison, scenarioError, setScenarioError, scenarioRefreshKey, setScenarioRefreshKey,
    attackPathQueue, setAttackPathQueue, attackPathQueueScanId, setAttackPathQueueScanId, loadingSnapshots,
    setLoadingSnapshots, loadingGraph, setLoadingGraph, loadingDiff, setLoadingDiff, error, setError, rateLimited,
    setRateLimited, diffError, setDiffError, comparisonRequested, setComparisonRequested, selectedNodeDetail,
    setSelectedNodeDetail, graphDiff, setGraphDiff, edgeChanges, setEdgeChanges, loadingEdgeChanges,
    setLoadingEdgeChanges, edgeChangesError, setEdgeChangesError, historySnapshots, setHistorySnapshots,
    loadingHistory, setLoadingHistory, driftScrubberPair, setDriftScrubberPair, driftLensActive, setDriftLensActive,
    driftFilter, setDriftFilter, changesOpen, setChangesOpen, evidenceLensActive, setEvidenceLensActive,
    evidenceFilter, setEvidenceFilter, selectedNode, setSelectedNode, selectedNodeId, setSelectedNodeId,
    selectedRelationship, setSelectedRelationship, selectedAttackPathKey, setSelectedAttackPathKey,
    requestedAttackPathKeyRef, searchQuery, setSearchQuery, searchResults, setSearchResults, searching, setSearching,
    investigationMode, setInvestigationMode, reachabilitySummary, setReachabilitySummary, loadingReachability,
    quietRootRef, mobileGraphView, setMobileGraphView, investigationRequestId, investigationAbort,
    investigationDirection, setInvestigationDirection, reachabilityError, setReachabilityError, blastRadius,
    setBlastRadius, loadingBlast, setLoadingBlast, blastError, setBlastError, rollupView, setRollupView, rollupStack,
    setRollupStack, rollupAutoDescendRef, rollupDismissed, setRollupDismissed, loadingRollup, setLoadingRollup,
    rollupChildPage, setRollupChildPage, rollupError, setRollupError, rollupUnavailable, setRollupUnavailable,
    rollupMapExpanded, setRollupMapExpanded, rollupSummaryRequested, setRollupSummaryRequested,
    restoreSummaryOnFilterReset, hoveredNodeId, setHoveredNodeId, pinnedFocusId, setPinnedFocusId, expandedClusterIds,
    setExpandedClusterIds, pathname, searchParams, filters, setFilters, initializedFocus, setInitializedFocus,
    seededFromUrlRef, requestedScanIdRef, requestedInvestigationRef, rollupPreferenceRef, explicitCanvasLens,
    canvasLens, canvasAgent, hasRequestedInvestigation, canvasLensRef, canvasAgentRef, selectedScenario,
    attackPathLens, firstScanSelectionRef, lastSyncedUrlRef, initialContextViewRef, captureModeFromLocation,
    captureMode, serverEntityTypes, serverRelationships, serverFilterKey, mergedGraphData, proposedGraphData,
    projectedGraphData, activeSnapshot, previousSnapshot, diffPair, viewingCurrentEstate, graphChanges, highlight,
    needsComparison, graphNodeById, activeScopePreset, attackPaths, effectiveSelectedAttackPathKey, selectedAttackPath,
    estateNodeCount, rollupEligible, rollupCanvasMode, rollupNavigationActive, rollupCanvasPending, rollupCanvasFailed,
    rollupCanvasOwnsPresentation, rollupItems, rollupDecisionAvailable, rollupDecisionActive, rollupChildPageKey,
    ancestryResolvedFor, soleScopeId, estateIssues, setEstateIssues, estateIssueSummary, rollupDisplayEdges,
  };
}

export type GraphPageData = ReturnType<typeof useGraphPageData>;
