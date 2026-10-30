"use client";

import { classifyApiOfflineKind, type ApiOfflineKind } from "@/lib/api-offline-kind";
import { InvestigationLifecyclePanel, InvestigationLifecycleStrip } from "@/components/investigation-lifecycle";
import { pathFindingId } from "@/lib/investigation-step-links";
import { InvestigationPageHeader } from "@/components/investigation-page-header";
import { InvestigationExploreMenu } from "@/components/investigation-explore-menu";
import { InvestigationNotices } from "@/components/investigation-notices";
import { InvestigationScanEvidence } from "@/components/investigation-scan-evidence";
import { InvestigationLoadError } from "@/components/investigation-load-error";
import { InvestigationFilteredEmpty } from "@/components/investigation-filtered-empty";
import { PathReachSummary } from "@/components/path-reach-summary";
import { PathExploitStory } from "@/components/path-exploit-story";
import { usePathExploitStory } from "@/hooks/use-path-exploit-story";

import { investigationHref, investigationView } from "@/lib/investigation-url";
import { selectAttackPathQueue } from "@/lib/attack-path-queue";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Loader2 } from "lucide-react";

import { ApiOfflineState } from "@/components/api-offline-state";
import { userFacingApiErrorMessage } from "@/lib/api-errors";
import { resolveSecurityGraphSurface } from "@/lib/security-graph-route";

import type { RankedPathRow } from "@/components/ranked-path-list";
import { AttackPathTechniqueChain } from "@/components/attack-path-technique-chain";
import { AttackPathCorrelationProof } from "@/components/attack-path-correlation-proof";
import { ExposurePathCommandCenter, type ExposurePathView } from "@/components/exposure-path-command-center";
import { InvestigationPathWorkspace, InvestigationTools } from "@/components/investigation-path-workspace";
import { GraphRemediationPriorities } from "@/components/graph-remediation-priorities";
import { DeployGatePanel } from "@/components/deploy-gate-panel";
import { ExposurePathLens } from "@/components/exposure-path-lens";
import { GraphPanelSkeleton } from "@/components/graph-state-panels";
import { GraphCampaignPanel } from "@/components/graph-campaign-panel";
import { GraphCorrelationWorkflow } from "@/components/graph-correlation-workflow";
import { GraphPathQueueContinuation } from "@/components/graph-path-queue-continuation";
import { useAuthState } from "@/components/auth-provider";
import {
  GraphPresetControls,
  type InvestigationPresetFilters,
} from "@/components/graph-preset-controls";
import { InvestigationFilterChips } from "@/components/investigation-filter-chips";
import { PathVendorScopeChips } from "@/components/path-vendor-scope-chips";
import { CROSS_VENDOR_PARAM, crossVendorRequest, crossVendorScopeLabel, parseCrossVendor } from "@/lib/path-vendor-scope";
import { parseInvestigationStep, type InvestigationStep } from "@/components/investigation-step-strip";
import {
  api,
  type FixFirstGraphViewResponse,
  type FixFirstPathCard,
  type GraphAttackCampaign,
  type GraphCorrelationRun,
  type GraphSnapshot,
  type PostureResponse,
  type UnifiedGraphResponse,
} from "@/lib/api";
import {
  attackPathKey, attackPathRoleChain, buildFindingsHref, buildGraphInvestigationHref, buildSecurityGraphHref,
  descriptiveAttackPathTitle, dedupeAttackPathsForPresentation, graphPathQueueCounts,
  investigationRootForAttackPath, labelsForAttackPathType, matchesAttackPathFocus, mergeAttackPathGraphPages,
  rankedAttackPathRows, recommendedAttackPathActions, toAttackCardNodes, toExposurePathFromAttackPath,
  withCanonicalExposurePresentation,
} from "@/lib/attack-paths";
import { FindingInvestigationContext } from "@/components/finding-investigation-context";
import { buildFindingAssetHref, withFindingContext } from "@/lib/finding-investigation-href";
import { attackPathLoadErrorCopy, emptyAttackPathQueueCopy } from "@/lib/investigation-queue-copy";
import { buildCorrelationOutcome } from "@/lib/correlation-outcome";
import { clientQueueFocus, emptyQueueCopy, focusedPathEmptyState, serverPathFocus, sourceSnapshotFallback } from "@/lib/finding-path-focus";
import { InvestigationEmptyQueue } from "@/components/investigation-empty-queue";
import { SecurityGraphInvestigation } from "@/components/security-graph-investigation";
import { GraphSurface } from "@/app/graph/graph-surface";
import type { UnifiedGraphData, UnifiedNode } from "@/lib/graph-schema";
import { investigationEstateMode } from "@/lib/investigation-estate-mode";
import { useCaptureMode } from "@/lib/use-capture-mode";
import { useSelectedPathGraph } from "@/hooks/use-selected-path-graph";
import {
  buildCorrelationPathHref, buildCorrelationRemediationHref, focusCorrelationPathTarget,
  latestCompletedCorrelation, selectInitialGraphSnapshot,
} from "@/lib/security-graph-focus";
import {
  collectPathEnvironments, filterAttackPathsForInvestigation, filterInvestigationQuestion,
} from "@/lib/investigation-path-filters";

const EMPTY_INVESTIGATION_FILTERS: InvestigationPresetFilters = {
  severity: null,
  layer: null,
  evidenceTier: null,
  environment: null,
};

/** First/next fetch size for GET /v1/graph/attack-paths (API offset paging). */
const ATTACK_PATH_FETCH_PAGE = 10;
const ATTACK_PATH_QUEUE_PAGE_SIZE = 10;
const FIX_FIRST_CARD_LIMIT = 10;
const DEFAULT_SNAPSHOT_CHIP_COUNT = 3;

function AttackPathInvestigationContent() {
  const captureMode = useCaptureMode();
  const searchParams = useSearchParams();
  const correlationCaptureMode = captureMode && searchParams.get("correlation") === "1";
  const requestedPathMode = searchParams.get("path");
  const requestedPathScanId = searchParams.get("scan");
  const focusedTopPathRef = useRef<string | null>(null);
  const router = useRouter();
  const pathname = usePathname();
  const [snapshots, setSnapshots] = useState<GraphSnapshot[]>([]);
  const [latestCorrelationRun, setLatestCorrelationRun] = useState<GraphCorrelationRun | null>(null);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [currentEstateId, setCurrentEstateId] = useState("");
  const [graphData, setGraphData] = useState<UnifiedGraphResponse | null>(null);
  const [fixFirstView, setFixFirstView] = useState<FixFirstGraphViewResponse | null>(null);
  const [posture, setPosture] = useState<PostureResponse | null>(null);
  const [loadingSnapshots, setLoadingSnapshots] = useState(true);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [loadingFixFirst, setLoadingFixFirst] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const [graphLoadError, setGraphLoadError] = useState<string | null>(null);
  const [fixFirstLoadError, setFixFirstLoadError] = useState<string | null>(null);
  const [apiErrorKind, setApiErrorKind] = useState<ApiOfflineKind>("network");
  const [reloadNonce, setReloadNonce] = useState(0);
  const retryLoad = useCallback(() => setReloadNonce((value) => value + 1), []);
  const [selectedAttackPathKey, setSelectedAttackPathKey] = useState<string | null>(null);
  const [focusApplied, setFocusApplied] = useState(false);
  const [showAllSnapshots, setShowAllSnapshots] = useState(false);
  const [visibleAttackPathCount, setVisibleAttackPathCount] = useState(ATTACK_PATH_QUEUE_PAGE_SIZE);
  const [loadingMorePaths, setLoadingMorePaths] = useState(false);
  const [morePathsError, setMorePathsError] = useState<string | null>(null);
  const pathPageRequest = useRef<AbortController | null>(null);
  const sharedSelectionScan = useRef<string | null>(null);
  const [investigationFocusMode, setInvestigationFocusMode] = useState(true);
  const [pathView, setPathView] = useState<ExposurePathView>(() => investigationView(searchParams.get("path_view")));
  const requestedQuestion = searchParams.get("question");
  const requestedSelectedPath = searchParams.get("selected_path");
  useEffect(() => setPathView(investigationView(searchParams.get("path_view"))), [searchParams]);
  const sharePathView = useCallback((view: ExposurePathView) => {
    setPathView(view);
    // Switching an already loaded representation must not navigate/remount
    // the workspace after its graph has scrolled into view.
    window.history.replaceState(null, "", investigationHref(pathname, searchParams.toString(), { path_view: view }));
  }, [pathname, searchParams]);
  const [investigationFilters, setInvestigationFilters] =
    useState<InvestigationPresetFilters>(EMPTY_INVESTIGATION_FILTERS);
  const [pinnedNodeId, setPinnedNodeId] = useState<string | null>(null);
  const [completedSteps, setCompletedSteps] = useState<Partial<Record<InvestigationStep, boolean>>>(
    {},
  );
  const [selectedCampaignId, setSelectedCampaignId] = useState<string | null>(null);

  const focus = useMemo(
    () => ({
      scanId: searchParams.get("scan") ?? "",
      cve: searchParams.get("cve") ?? "",
      packageName: searchParams.get("package") ?? "",
      agentName: searchParams.get("agent") ?? "",
      nodeId: searchParams.get("node") ?? "",
      findingId: searchParams.get("finding") ?? "",
      findingScanId: searchParams.get("finding_scan") ?? "",
      framework: searchParams.get("framework") ?? "",
      control: searchParams.get("control") ?? "",
      traceId: searchParams.get("trace") ?? searchParams.get("runtime_trace_id") ?? "",
      crossVendor: parseCrossVendor(searchParams.get(CROSS_VENDOR_PARAM)),
    }),
    [searchParams],
  );

  const investigationStep = parseInvestigationStep(searchParams.get("step"));
  const selectedScenarioId = searchParams.get("scenario");

  useEffect(() => {
    if (!selectedScenarioId || searchParams.get("state") === "current") return;
    const next = new URLSearchParams(searchParams.toString());
    next.set("state", "current");
    router.replace(`${pathname}?${next.toString()}`, { scroll: false });
  }, [pathname, router, searchParams, selectedScenarioId]);

  const setInvestigationStep = useCallback(
    (next: InvestigationStep) => {
      const params = new URLSearchParams(searchParams.toString());
      if (next === "path") params.delete("step");
      else params.set("step", next);
      // Impact answers in the graph. Other steps answer above the workspace and
      // keep the current representation: rewriting the view here re-scrolled the
      // graph over the answer the operator just asked for.
      if (next === "impact") params.set("path_view", "graph");
      const query = params.toString();
      router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
      setCompletedSteps((current) => ({ ...current, [next]: true }));
      if (next === "impact") {
        setPathView("graph");
        setInvestigationFocusMode(true);
      }
    },
    [pathname, router, searchParams],
  );

  const selectSnapshot = useCallback(
    (scanId: string) => {
      setSelectedScanId(scanId);
      const params = new URLSearchParams(searchParams.toString());
      params.set("scan", scanId);
      router.replace(`${pathname}?${params.toString()}`, { scroll: false });
    },
    [pathname, router, searchParams],
  );

  const openCorrelationPath = useCallback(
    (scanId: string) => {
      setSelectedScanId(scanId);
      setSelectedAttackPathKey(null);
      setFocusApplied(true);
      setInvestigationFocusMode(true);
      setPathView("path");
      setInvestigationFilters(EMPTY_INVESTIGATION_FILTERS);
      setSelectedCampaignId(null);
      setVisibleAttackPathCount(ATTACK_PATH_QUEUE_PAGE_SIZE);
      router.push(buildCorrelationPathHref(pathname, searchParams, scanId), { scroll: false });
      window.requestAnimationFrame(() => {
        focusCorrelationPathTarget(document);
      });
    },
    [pathname, router, searchParams],
  );

  const handleStepHint = useCallback(
    (step: "expand" | "impact" | "fix") => {
      const lifecycleStep: InvestigationStep = step === "expand" ? "impact" : step;
      setCompletedSteps((current) => ({ ...current, path: true, [lifecycleStep]: true }));
      if (investigationStep === "path" && lifecycleStep === "impact") {
        setInvestigationStep("impact");
      }
    },
    [investigationStep, setInvestigationStep],
  );

  const hasFocusContext = Boolean(
    focus.cve || focus.packageName || focus.agentName || focus.nodeId || focus.findingId || focus.control,
  );

  useEffect(() => {
    // Pinning the already loaded snapshot into a shared path URL must not
    // unmount the workspace and discard its announcement or scroll target.
    const sharedScan = sharedSelectionScan.current;
    sharedSelectionScan.current = null;
    if (focus.scanId && sharedScan === focus.scanId) return;
    let cancelled = false;

    async function load() {
      setLoadingSnapshots(true);
      try {
        const [snapshotList, postureData, correlationList, currentScope] = await Promise.all([
          // windowDays: 0 keeps all retained snapshots visible (#4009).
          api.getGraphSnapshots(25, 0),
          api.getPosture().catch(() => null),
          api.listGraphCorrelations(20).catch(() => null),
          !focus.scanId || focus.scanId.startsWith("current-estate:") ? api.getInventorySummary() : Promise.resolve(null),
        ]);
        if (cancelled) return;
        setSnapshots(snapshotList);
        setCurrentEstateId(currentScope?.scan_id ?? "");
        setPosture(postureData);
        const latestCorrelation = latestCompletedCorrelation(correlationList?.items ?? []);
        setLatestCorrelationRun(latestCorrelation);
        const requestedScanId = focus.scanId;
        const initialScanId = selectInitialGraphSnapshot(
          snapshotList,
          requestedScanId,
          latestCorrelation,
          currentScope?.scan_id ?? focus.scanId,
        );
        setSelectedScanId(initialScanId);
        setApiError(null);
        setGraphLoadError(null);
      } catch (error) {
        if (cancelled) return;
        setApiError(userFacingApiErrorMessage(error, "Failed to load graph snapshots"));
        setApiErrorKind(classifyApiOfflineKind(error));
        setSnapshots([]);
        setLatestCorrelationRun(null);
        setGraphData(null);
        setFixFirstView(null);
        setGraphLoadError(null);
      } finally {
        if (!cancelled) setLoadingSnapshots(false);
      }
    }

    void load();
    return () => {
      cancelled = true;
    };
  }, [focus.scanId, reloadNonce]);

  useEffect(() => {
    if (!selectedScanId) {
      setGraphData(null);
      setFixFirstView(null);
      setSelectedAttackPathKey(null);
      setGraphLoadError(null);
      setFixFirstLoadError(null);
      return;
    }

    let cancelled = false;
    setMorePathsError(null);

    setGraphData(null);
    setFixFirstView(null);
    setGraphLoadError(null);
    setFixFirstLoadError(null);

    async function loadAttackPaths() {
      setLoadingGraph(true);
      setLoadingMorePaths(false);
      setVisibleAttackPathCount(ATTACK_PATH_QUEUE_PAGE_SIZE);
      try {
        const graph = await api.getGraphAttackPaths({
          scanId: selectedScanId,
          offset: 0,
          limit: ATTACK_PATH_FETCH_PAGE,
          ...serverPathFocus({ nodeId: focus.nodeId, findingId: focus.findingId, cve: focus.cve, framework: focus.framework, control: focus.control }),
          ...crossVendorRequest(focus.crossVendor),
        });
        if (cancelled) return;
        const sourceScan = sourceSnapshotFallback({
          selectedScanId,
          findingScanId: focus.findingScanId,
          focus: graph.focus ?? null,
          matches: graph.attack_paths?.length ?? 0,
        });
        if (sourceScan) {
          // Read the live URL here: depending on searchParams would reload paths on every step change.
          const params = new URLSearchParams(window.location.search);
          params.set("scan", sourceScan);
          params.set("source_snapshot", "1");
          router.replace(`${window.location.pathname}?${params.toString()}`, { scroll: false });
          return;
        }
        setGraphData(graph);
        setApiError(null);
        setGraphLoadError(null);
      } catch (error) {
        if (cancelled) return;
        setGraphData(null);
        setGraphLoadError(userFacingApiErrorMessage(error, "Failed to load security graph"));
        setApiErrorKind(classifyApiOfflineKind(error));
      } finally {
        if (!cancelled) setLoadingGraph(false);
      }
    }

    async function loadFixFirstEnrichment() {
      setLoadingFixFirst(true);
      try {
        const view = await api.getFixFirstGraphView({
          scanId: selectedScanId,
          cve: focus.cve || undefined,
          packageName: focus.packageName || undefined,
          agentName: focus.agentName || undefined,
          limit: FIX_FIRST_CARD_LIMIT,
        });
        if (cancelled) return;
        setFixFirstView(view);
        setFixFirstLoadError(null);
      } catch (error) {
        if (cancelled) return;
        setFixFirstView(null);
        setFixFirstLoadError(userFacingApiErrorMessage(error, "Fix guidance is unavailable"));
      } finally {
        if (!cancelled) setLoadingFixFirst(false);
      }
    }

    void loadAttackPaths();
    void loadFixFirstEnrichment();
    return () => {
      cancelled = true;
      pathPageRequest.current?.abort();
      pathPageRequest.current = null;
    };
  }, [focus.agentName, focus.control, focus.crossVendor, focus.cve, focus.findingId, focus.findingScanId, focus.framework, focus.nodeId, focus.packageName, reloadNonce, router, selectedScanId]);

  const selectedSnapshot = useMemo(
    () => snapshots.find((snapshot) => snapshot.scan_id === selectedScanId) ?? null,
    [snapshots, selectedScanId],
  );
  // Stale/empty snapshots (0 persisted nodes) and unrelated older scans pile up
  // in a long-lived graph store and drown the real ones in the chip row.
  // Default to the current scan plus at most a couple of recent populated
  // snapshots; "show all" reveals every empty and older one on demand.
  const activeSnapshots = useMemo(
    () => snapshots.filter((snapshot) => snapshot.node_count > 0 || snapshot.scan_id === selectedScanId),
    [snapshots, selectedScanId],
  );
  const displayedSnapshots = useMemo(() => {
    if (showAllSnapshots) return snapshots;
    // Current scan first, then the most recent populated snapshots — never the
    // empty/unrelated ones up front.
    const current = activeSnapshots.filter((snapshot) => snapshot.scan_id === selectedScanId);
    const rest = activeSnapshots.filter((snapshot) => snapshot.scan_id !== selectedScanId);
    return [...current, ...rest].slice(0, DEFAULT_SNAPSHOT_CHIP_COUNT);
  }, [activeSnapshots, showAllSnapshots, selectedScanId, snapshots]);
  const hiddenSnapshotCount = Math.max(0, snapshots.length - displayedSnapshots.length);
  const estateMode = investigationEstateMode(selectedSnapshot?.node_count ?? 0, selectedScanId || undefined);

  const fixFirstCards = useMemo(() => fixFirstView?.cards ?? [], [fixFirstView?.cards]);

  const graphNodeById = useMemo(() => {
    const nodes = new Map((graphData?.nodes ?? []).map((node) => [node.id, node]));
    for (const card of fixFirstCards) {
      for (const node of card.nodes ?? []) {
        nodes.set(node.id, node);
      }
    }
    return nodes;
  }, [fixFirstCards, graphData?.nodes]);

  // Name the focus in words; the raw node id stays in the URL and node details.
  const focusLabel = useMemo(() => {
    const nodeLabel = focus.nodeId
      ? graphNodeById.get(graphData?.focus?.node_id || focus.nodeId)?.label || focus.packageName || focus.cve || "Selected asset"
      : "";
    const controlLabel = focus.framework && focus.control ? `Control ${focus.control} evidence` : "";
    const parts = [...new Set([crossVendorScopeLabel(focus.crossVendor), controlLabel, nodeLabel, focus.cve, focus.packageName, focus.agentName].filter(Boolean))];
    return parts.length > 0 ? parts.join(" · ") : null;
  }, [focus.agentName, focus.control, focus.crossVendor, focus.cve, focus.framework, focus.nodeId, focus.packageName, graphData?.focus?.node_id, graphNodeById]);

  const cardByPathKey = useMemo(() => {
    const next = new Map<string, FixFirstPathCard>();
    for (const card of fixFirstCards) {
      next.set(attackPathKey(card.attack_path), card);
    }
    return next;
  }, [fixFirstCards]);

  const campaigns = useMemo<GraphAttackCampaign[]>(
    () => fixFirstView?.attack_campaigns ?? [],
    [fixFirstView?.attack_campaigns],
  );
  const selectedCampaign = useMemo(
    () => campaigns.find((campaign) => campaign.campaign_id === selectedCampaignId) ?? null,
    [campaigns, selectedCampaignId],
  );

  const serverFocus = graphData?.focus ?? null;
  const allAttackPaths = useMemo(() => selectAttackPathQueue(
    graphData?.attack_paths,
    fixFirstCards.map((card) => card.attack_path),
    graphNodeById,
    clientQueueFocus(hasFocusContext ? focus : {}, Boolean(serverFocus)),
    selectedCampaign?.member_paths,
  ), [fixFirstCards, focus, graphData?.attack_paths, graphNodeById, hasFocusContext, selectedCampaign, serverFocus]);
  const tenantHasGraphData = snapshots.some((snapshot) => snapshot.node_count > 0)
    || (graphData?.count_metadata?.snapshot_total ?? 0) > 0;
  const focusedEmpty = focusedPathEmptyState({
    serverFocused: Boolean(serverFocus),
    coversAllMatches: serverFocus?.covers_all_matches ?? false,
    cve: focus.cve,
    currentEstate: selectedScanId.startsWith("current-estate:"),
  });
  const relatedPackagePathsHref = useMemo(() => {
    if (!focus.findingId || !focus.nodeId || !focus.cve || allAttackPaths.length > 0) return null;
    if (serverFocus) {
      // The server checked the whole queue for this occurrence; offering the
      // package's other paths is a deliberate, labelled widening of scope.
      const params = new URLSearchParams(searchParams.toString());
      params.delete("finding");
      params.set("related_finding", focus.findingId);
      return `${pathname}?${params.toString()}`;
    }
    const relatedFocus = { ...focus, findingId: "" };
    const hasRelatedPath = [...(graphData?.attack_paths ?? []), ...fixFirstCards.map(card => card.attack_path)]
      .some(path => matchesAttackPathFocus(path, graphNodeById, relatedFocus));
    if (!hasRelatedPath) return null;
    // A deliberate scope change, never an inferred association to this finding.
    const params = new URLSearchParams(searchParams.toString());
    params.delete("finding");
    params.set("related_finding", focus.findingId);
    return `${pathname}?${params.toString()}`;
  }, [allAttackPaths.length, fixFirstCards, focus, graphData?.attack_paths, graphNodeById, pathname, searchParams, serverFocus]);
  const presentationAttackPaths = useMemo(
    () => dedupeAttackPathsForPresentation(allAttackPaths, graphNodeById),
    [allAttackPaths, graphNodeById],
  );
  const attackPaths = useMemo(
    () => filterInvestigationQuestion(filterAttackPathsForInvestigation(presentationAttackPaths, graphNodeById, investigationFilters), graphNodeById, requestedQuestion),
    [graphNodeById, investigationFilters, presentationAttackPaths, requestedQuestion],
  );
  const pathEnvironments = useMemo(
    () => collectPathEnvironments(allAttackPaths, graphNodeById),
    [allAttackPaths, graphNodeById],
  );
  const visibleAttackPaths = useMemo(
    () => attackPaths.slice(0, Math.min(visibleAttackPathCount, attackPaths.length)),
    [attackPaths, visibleAttackPathCount],
  );
  const filtersNarrowQueue =
    Boolean(selectedCampaign?.member_paths?.length) ||
    Object.values(investigationFilters).some((value) => Boolean(value));
  const pathHasMoreFromApi = Boolean(graphData?.pagination?.has_more);
  const hiddenLoadedAttackPathCount = Math.max(0, attackPaths.length - visibleAttackPaths.length);

  const loadMoreAttackPaths = useCallback(async () => {
    if (hiddenLoadedAttackPathCount > 0) {
      setVisibleAttackPathCount((current) =>
        Math.min(attackPaths.length, current + ATTACK_PATH_QUEUE_PAGE_SIZE),
      );
      return;
    }
    if (!pathHasMoreFromApi || !selectedScanId || !graphData || pathPageRequest.current) return;
    const offset = graphData.pagination?.offset ?? 0;
    const limit = graphData.pagination?.limit ?? ATTACK_PATH_FETCH_PAGE;
    // Server has_more uses offset+limit < total; advance by the requested page size.
    const nextOffset = offset + limit;
    const controller = new AbortController();
    pathPageRequest.current = controller;
    setLoadingMorePaths(true);
    setMorePathsError(null);
    try {
      const nextPage = await api.getGraphAttackPaths({
        scanId: selectedScanId,
        offset: nextOffset,
        snapshotGeneration: graphData.snapshot_generation,
        limit: ATTACK_PATH_FETCH_PAGE,
        ...serverPathFocus(focus),
        ...crossVendorRequest(focus.crossVendor),
      }, { signal: controller.signal });
      if (controller.signal.aborted) return;
      // Validate before scheduling a state update; preserve loaded evidence on mismatch.
      const merged = mergeAttackPathGraphPages(graphData, nextPage);
      setGraphData(merged);
      setVisibleAttackPathCount((current) => current + ATTACK_PATH_QUEUE_PAGE_SIZE);
    } catch (error) {
      if (!controller.signal.aborted) setMorePathsError(userFacingApiErrorMessage(error, "Failed to load more attack paths"));
    } finally {
      if (pathPageRequest.current === controller) {
        pathPageRequest.current = null;
        setLoadingMorePaths(false);
      }
    }
  }, [
    attackPaths.length,
    focus,
    graphData,
    hiddenLoadedAttackPathCount,
    pathHasMoreFromApi,
    selectedScanId,
  ]);

  const queueContinuation = <GraphPathQueueContinuation graph={graphData} matches={attackPaths.length}
    pageSize={ATTACK_PATH_QUEUE_PAGE_SIZE} hiddenMatches={hiddenLoadedAttackPathCount} narrowed={filtersNarrowQueue || hasFocusContext}
    loading={loadingMorePaths} error={morePathsError} onMore={() => void loadMoreAttackPaths()} />;

  const rankedRows = useMemo<RankedPathRow[]>(
    () =>
      rankedAttackPathRows(visibleAttackPaths, fixFirstCards).flatMap(({ path, card, rank, key }) => {
        const pathNodes = toAttackCardNodes(path, graphNodeById);
        if (pathNodes.length === 0) return [];
        const row: RankedPathRow = {
          key,
          selectionKey: attackPathKey(path),
          rank,
          title: descriptiveAttackPathTitle(pathNodes),
          cve: path.vuln_ids[0] ?? null,
          riskScore: path.composite_risk,
          nodeCount: path.hops.length,
          agents: labelsForAttackPathType(path, graphNodeById, "agent").length,
          roleChain: attackPathRoleChain(path, graphNodeById),
        };
        if (card?.rank_meta?.tool_capabilities?.length) {
          row.capabilityTags = card.rank_meta.tool_capabilities;
        }
        if (card?.rank_meta?.environments?.length) {
          row.environmentTags = card.rank_meta.environments;
        }
        return [row];
      }),
    [fixFirstCards, graphNodeById, visibleAttackPaths],
  );
  const pathQueueCounts = useMemo(
    () => graphPathQueueCounts(graphData, rankedRows.length),
    [graphData, rankedRows.length],
  );

  const selectedAttackPath = useMemo(
    () =>
      selectedAttackPathKey
        ? attackPaths.find((path) => attackPathKey(path) === selectedAttackPathKey) ?? null
        : attackPaths[0] ?? null,
    [attackPaths, selectedAttackPathKey],
  );
  useEffect(() => {
    if (requestedPathMode !== "top" || requestedPathScanId !== selectedScanId) {
      focusedTopPathRef.current = null;
      return;
    }
    const topPath = attackPaths[0];
    if (!topPath) return;
    const topPathKey = attackPathKey(topPath);
    const focusKey = `${selectedScanId}:${topPathKey}`;
    if (focusedTopPathRef.current === focusKey) return;
    if (selectedAttackPathKey !== topPathKey) {
      setSelectedAttackPathKey(topPathKey);
      return;
    }
    focusedTopPathRef.current = focusKey;
    const frame = window.requestAnimationFrame(() => {
      focusCorrelationPathTarget(document);
    });
    return () => window.cancelAnimationFrame(frame);
  }, [attackPaths, requestedPathMode, requestedPathScanId, selectedAttackPathKey, selectedScanId]);
  const investigationRoot = useMemo(
    () =>
      selectedAttackPath
        ? investigationRootForAttackPath(selectedAttackPath, graphNodeById, focus)
        : null,
    [focus, graphNodeById, selectedAttackPath],
  );
  const fullGraphHref = useMemo(() => {
    // Opening the full graph from a selected path keeps that path, not just its first entity.
    if (selectedAttackPath) {
      const params = new URLSearchParams({ lens: "attack-path", path: attackPathKey(selectedAttackPath) });
      if (selectedScanId) params.set("scan", selectedScanId);
      return withFindingContext(`/graph?${params.toString()}`, searchParams);
    }
    if (investigationRoot) {
      return withFindingContext(buildGraphInvestigationHref({
        scanId: selectedScanId || undefined,
        agentName: focus.agentName || undefined,
        rootId: investigationRoot.id,
        rootLabel: investigationRoot.label,
      }), searchParams);
    }

    const params = new URLSearchParams();
    if (selectedScanId) params.set("scan", selectedScanId);
    if (focus.agentName) params.set("agent", focus.agentName);
    const query = params.toString();
    if (query) params.set("lens", "lineage");
    return withFindingContext(params.size > 0 ? `/security-graph?${params.toString()}` : "/security-graph?lens=lineage", searchParams);
  }, [focus.agentName, investigationRoot, selectedScanId, searchParams, selectedAttackPath]);
  const resetFocusHref = useMemo(
    () => buildSecurityGraphHref({ scanId: selectedScanId || undefined }),
    [selectedScanId],
  );

  const selectedFixFirstCard = useMemo(
    () => (selectedAttackPath ? cardByPathKey.get(attackPathKey(selectedAttackPath)) ?? null : null),
    [cardByPathKey, selectedAttackPath],
  );
  const selectedPathGraph = useSelectedPathGraph({
    graph: graphData as UnifiedGraphData | null,
    path: selectedAttackPath,
    scanId: selectedScanId,
    enabled: pathView === "graph",
  });
  const pathStory = usePathExploitStory({ path: selectedAttackPath, scanId: selectedScanId });
  const selectedExposurePath = useMemo(
    () => {
      if (!selectedAttackPath) return null;
      const exposurePath = selectedFixFirstCard?.exposure_path ??
        toExposurePathFromAttackPath(selectedAttackPath, graphNodeById, {
          scanId: selectedScanId || undefined,
          rank: selectedFixFirstCard?.rank,
        });
      return withCanonicalExposurePresentation(exposurePath, graphNodeById);
    },
    [graphNodeById, selectedAttackPath, selectedFixFirstCard, selectedScanId],
  );

  const selectedPathActions = useMemo(() => {
    if (!selectedAttackPath) return [];
    const actions = selectedFixFirstCard?.next_actions
      ?? recommendedAttackPathActions(selectedAttackPath, graphNodeById, { scanId: selectedScanId || undefined });
    const finding = selectedFixFirstCard?.affected.finding_labels?.[0] ?? selectedAttackPath.vuln_ids[0];
    const packageNode = selectedAttackPath.hops
      .map((hop) => graphNodeById.get(hop))
      .find((node) => node?.entity_type === "package");
    return actions.map((action) => action.href.split("?", 1)[0] === "/remediation"
      ? { ...action, href: buildCorrelationRemediationHref(action.href, selectedScanId, finding, packageNode?.label) }
      : action);
  }, [graphNodeById, selectedAttackPath, selectedFixFirstCard, selectedScanId]);
  const correlationOutcome = useMemo(() => buildCorrelationOutcome({
    path: selectedAttackPath, card: selectedFixFirstCard, actions: selectedPathActions, nodeById: graphNodeById,
    scanId: selectedScanId, graphScanId: graphData?.scan_id, fixFirstScanId: fixFirstView?.scan_id,
  }), [fixFirstView?.scan_id, graphData?.scan_id, graphNodeById, selectedAttackPath, selectedFixFirstCard, selectedPathActions, selectedScanId]);

  const showCorrelationOverview = searchParams.get("correlation") === "1"
    && latestCorrelationRun?.output_scan_id === selectedScanId
    && Boolean(correlationOutcome)
    && requestedPathMode !== "top"
    && (!hasFocusContext || correlationCaptureMode);

  const emptyGraphState = useMemo(
    () => emptyAttackPathQueueCopy(graphData?.stats.analysis_status?.attack_path_fusion, hasFocusContext, focusLabel),
    [focusLabel, graphData?.stats.analysis_status, hasFocusContext],
  );
  const graphErrorState = useMemo(() => attackPathLoadErrorCopy(graphLoadError), [graphLoadError]);

  const loadingGraphMessage = focusLabel
    ? `Loading paths for ${focusLabel}…`
    : "Loading exposure paths…";

  useEffect(() => {
    setFocusApplied(false);
    setVisibleAttackPathCount(ATTACK_PATH_QUEUE_PAGE_SIZE);
  }, [focus.agentName, focus.crossVendor, focus.cve, focus.findingId, focus.nodeId, focus.packageName, selectedScanId]);

  useEffect(() => {
    setPinnedNodeId(focus.nodeId || null);
  }, [focus.nodeId]);

  useEffect(() => {
    if (!selectedAttackPathKey) return;
    const selectedIndex = attackPaths.findIndex((path) => attackPathKey(path) === selectedAttackPathKey);
    if (selectedIndex < 0 || selectedIndex < visibleAttackPathCount) return;
    const nextPageCount =
      Math.ceil((selectedIndex + 1) / ATTACK_PATH_QUEUE_PAGE_SIZE) *
      ATTACK_PATH_QUEUE_PAGE_SIZE;
    setVisibleAttackPathCount(Math.min(attackPaths.length, nextPageCount));
  }, [attackPaths, selectedAttackPathKey, visibleAttackPathCount]);

  useEffect(() => {
    if (attackPaths.length === 0) {
      setSelectedAttackPathKey(null);
      return;
    }
    if (requestedSelectedPath && attackPaths.some(path => attackPathKey(path) === requestedSelectedPath)) {
      setSelectedAttackPathKey(requestedSelectedPath);
      return;
    }
    if (!focusApplied && hasFocusContext) {
      const focusedPath =
        attackPaths.find((path) => matchesAttackPathFocus(path, graphNodeById, focus)) ?? attackPaths[0]!;
      setSelectedAttackPathKey(attackPathKey(focusedPath));
      setFocusApplied(true);
      return;
    }
    if (!selectedAttackPathKey) {
      setSelectedAttackPathKey(attackPathKey(attackPaths[0]!));
      return;
    }
    if (!attackPaths.some((path) => attackPathKey(path) === selectedAttackPathKey)) {
      setSelectedAttackPathKey(attackPathKey(attackPaths[0]!));
    }
  }, [attackPaths, focus, focusApplied, graphNodeById, hasFocusContext, requestedSelectedPath, selectedAttackPathKey]);

  if (apiError && !loadingSnapshots && snapshots.length === 0) {
    const fallbackTitle = apiErrorKind === "network" ? "Cannot load the security graph" : undefined;
    return (
      <ApiOfflineState
        title={fallbackTitle}
        detail={apiError}
        kind={apiErrorKind}
        onRetry={retryLoad}
      />
    );
  }

  return (
    <div className={captureMode ? "space-y-2" : "space-y-4"}>
      <InvestigationPageHeader
        focus={focusLabel || (selectedScanId?.startsWith("current-estate:") ? "Current tenant estate" : "Selected scan snapshot")}
        context={<FindingInvestigationContext compact />}
        pinned={pinnedNodeId ? graphNodeById.get(pinnedNodeId)?.label || "Selected asset" : null}
        steps={!captureMode ? (
          <InvestigationLifecycleStrip step={investigationStep} onStepChange={setInvestigationStep} completed={completedSteps}
            findingId={pathFindingId(selectedAttackPath, selectedAttackPath?.hops.flatMap(id => graphNodeById.get(id) ?? []) ?? [], focus.findingId)} />
        ) : null}
        menu={
          <InvestigationExploreMenu
            question={requestedQuestion}
            onQuestion={(question) => router.replace(investigationHref(pathname, searchParams.toString(), { question, selected_path: null }), { scroll: false })}
            onBlastRadius={() => setInvestigationStep("impact")}
            snapshot={selectedSnapshot}
            scanId={selectedScanId}
            exposurePath={selectedExposurePath}
            fullGraphHref={fullGraphHref}
          />
        }
      />
      <GraphRemediationPriorities view={fixFirstView} scanId={graphData?.scan_id || selectedScanId} />
      <InvestigationNotices
        question={Boolean(requestedQuestion)}
        sharedPathMissing={Boolean(requestedSelectedPath && graphData && !allAttackPaths.some(path => attackPathKey(path) === requestedSelectedPath))}
        sourceSnapshot={searchParams.get("source_snapshot") === "1" && focus.scanId ? focus.scanId : null}
        relatedFinding={Boolean(searchParams.get("related_finding"))}
        scenario={Boolean(selectedScenarioId)}
      />
      {!captureMode ? (
        <InvestigationLifecyclePanel step={investigationStep} path={selectedAttackPath} nodeById={graphNodeById}
          scanId={selectedScanId} findingId={focus.findingId} tenantId={graphData?.tenant_id} snapshotGeneration={graphData?.snapshot_generation} />
      ) : null}
      {showCorrelationOverview ? (
        <GraphCorrelationWorkflow snapshots={snapshots} initialRun={latestCorrelationRun} outcome={correlationOutcome} onOpenSnapshot={openCorrelationPath} />
      ) : null}

      {loadingSnapshots || loadingGraph ? (
        <section className="rounded-3xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
          <GraphPanelSkeleton
            title="Loading security graph"
            detail={loadingGraphMessage}
          />
        </section>
      ) : graphLoadError ? (
        <InvestigationLoadError copy={graphErrorState} retryHref={fullGraphHref} resetFocusHref={hasFocusContext ? resetFocusHref : null} busy={apiErrorKind === "busy"} onRetry={retryLoad} />
      ) : allAttackPaths.length === 0 ? (
        <InvestigationEmptyQueue
          analysisStatus={graphData?.stats.analysis_status?.attack_path_fusion}
          copy={emptyQueueCopy({ focused: focusedEmpty, morePagesUnloaded: pathHasMoreFromApi, relatedHref: relatedPackagePathsHref, fallback: emptyGraphState })}
          suggestions={emptyGraphState.suggestions}
          tenantHasGraphData={tenantHasGraphData}
          continuation={serverFocus ? null : queueContinuation}
          neighbourhood={focus.nodeId ? {
            href: buildFindingAssetHref({ findingScanId: searchParams.get("finding_scan") || focus.scanId, nodeId: serverFocus?.node_id || focus.nodeId, findingId: focus.findingId, scanId: selectedScanId }),
            label: serverFocus ? "Open package neighbourhood" : "Inspect linked asset",
          } : null}
          relatedHref={relatedPackagePathsHref}
          fullGraphHref={fullGraphHref}
          findingsHref={buildFindingsHref({ scanId: selectedScanId || undefined })}
          resetFocusHref={hasFocusContext ? resetFocusHref : null}
        />
      ) : attackPaths.length === 0 ? (
        <InvestigationFilteredEmpty
          filters={investigationFilters}
          onFiltersChange={setInvestigationFilters}
          onClear={() => setInvestigationFilters(EMPTY_INVESTIGATION_FILTERS)}
          environments={pathEnvironments}
          morePages={pathHasMoreFromApi}
          continuation={queueContinuation}
        />
      ) : showCorrelationOverview ? null : (
        <InvestigationPathWorkspace
          rows={rankedRows}
          selectedKey={selectedAttackPath ? attackPathKey(selectedAttackPath) : null}
          onSelect={(key) => {
            sharedSelectionScan.current = focus.scanId === selectedScanId ? null : selectedScanId;
            setSelectedAttackPathKey(key);
            // This path is already loaded. Share its selection without a route
            // transition that can replace the workspace after it scrolls.
            window.history.replaceState(null, "", investigationHref(pathname, searchParams.toString(), { selected_path: key, path_view: "path", scan: selectedScanId }));
            setCompletedSteps((current) => ({ ...current, path: true }));
            setPathView("path");
          }}
          title={`${pathQueueCounts.renderedRows} shown · ${pathQueueCounts.returnedRows} loaded paths`}
          coverageNotice={
            loadingFixFirst ? "Ranked paths are ready; fix guidance is still loading."
              : fixFirstLoadError ? "Ranked paths are ready; fix guidance is temporarily unavailable."
                : pathQueueCounts.truncated ? "More paths are available. Open paths and filters to load the next page."
                  : selectedCampaign ? `Filtered to ${selectedCampaign.crown_jewel_label || selectedCampaign.crown_jewel}.`
                    : undefined
          }
          subtitle={`${pathQueueCounts.queueRows} from the path queue. ${pathQueueCounts.snapshotTotal} snapshot paths. ${pathQueueCounts.materializedPaths} materialized · ${pathQueueCounts.derivedPaths} derived. ${
            graphData?.count_metadata?.source === "derived_graph_paths" ? "Ranked from bounded graph traversal." : "Ranked from persisted scan paths."
          }`}
          queueInitiallyOpen={Boolean(focus.crossVendor)} scope={<PathVendorScopeChips scanId={selectedScanId} value={focus.crossVendor}
            onChange={scope => router.replace(investigationHref(pathname, searchParams.toString(), { [CROSS_VENDOR_PARAM]: scope || null, selected_path: null }), { scroll: false })} />}
          filters={
            <>
              <InvestigationFilterChips
                filters={investigationFilters}
                onChange={setInvestigationFilters}
                environments={pathEnvironments}
              />
              <GraphPresetControls
                filters={investigationFilters}
                onApply={setInvestigationFilters}
              />
              {focusLabel ? (
                <p className="text-xs text-emerald-700 dark:text-emerald-300">Focused: {focusLabel}</p>
              ) : null}
              {focus.traceId ? (
                <p className="text-xs text-sky-700 dark:text-sky-300">
                  Runtime trace pin: <span className="font-mono">{focus.traceId}</span>
                </p>
              ) : null}
            </>
          }
          queueFooter={queueContinuation}
          detail={
            selectedExposurePath ? (
              <ExposurePathCommandCenter
                title={selectedFixFirstCard?.title}
                path={selectedExposurePath}
                actions={selectedPathActions}
                scanId={selectedScanId || undefined}
                view={pathView}
                onViewChange={sharePathView}
                techniquesSlot={
                  selectedAttackPath ? (
                    <AttackPathCorrelationProof
                      path={selectedAttackPath}
                      riskReasons={selectedFixFirstCard?.risk_reasons}
                      nodes={selectedAttackPath.hops.map((id) => graphNodeById.get(id)).filter((node): node is UnifiedNode => Boolean(node))}
                    />
                  ) : null
                }
                detailsSlot={selectedAttackPath ? <AttackPathTechniqueChain path={selectedAttackPath} /> : null}
                graphSlot={
                  selectedAttackPath ? (
                    <div className="space-y-2">
                      {selectedPathGraph.message ? (
                        <div role="status" className="rounded-lg border border-border bg-muted/30 px-3 py-2 text-sm text-muted-foreground">
                          {selectedPathGraph.message}
                          {selectedPathGraph.canRetry ? (
                            <button type="button" className="ml-2 font-medium text-foreground underline" onClick={selectedPathGraph.retry}>Retry graph</button>
                          ) : null}
                        </div>
                      ) : null}
                      {selectedPathGraph.loading ? <GraphPanelSkeleton title="Loading selected path" detail="Reading its nodes and relationships from this snapshot…" /> : null}
                      {selectedPathGraph.graph ? (
                        <SecurityGraphInvestigation
                          embedded
                          graph={selectedPathGraph.graph}
                          attackPath={selectedAttackPath}
                          focusMode={investigationFocusMode}
                          onFocusModeChange={setInvestigationFocusMode}
                          fullGraphHref={fullGraphHref}
                          loading={loadingGraph}
                          scanId={selectedScanId || undefined}
                          onPinnedNodeChange={setPinnedNodeId}
                          onStepHint={handleStepHint}
                          riskContext={pathStory.riskContext}
                        />
                      ) : null}
                      {pathStory.state.status === "absent" ? <PathReachSummary path={selectedAttackPath} scanId={selectedScanId} /> : <PathExploitStory story={pathStory} />}
                    </div>
                  ) : null
                }
              />
            ) : (
              <GraphPanelSkeleton title="Selecting path" detail="Preparing observed graph evidence…" />
            )
          }
          sideRail={
            <GraphCampaignPanel
              campaigns={campaigns}
              selectedCampaignId={selectedCampaignId}
              onSelect={(campaign) => {
                setSelectedCampaignId((current) =>
                  current === campaign.campaign_id ? null : campaign.campaign_id,
                );
                setVisibleAttackPathCount(ATTACK_PATH_QUEUE_PAGE_SIZE);
              }}
            />
          }
        />
      )}

      <InvestigationTools
        scope={
        <div className="space-y-4">
          {!showCorrelationOverview && (!captureMode || correlationCaptureMode) && snapshots.length > 0 ? (
            <GraphCorrelationWorkflow
              snapshots={snapshots}
              initialRun={latestCorrelationRun}
              outcome={correlationOutcome}
              onOpenSnapshot={openCorrelationPath}
            />
          ) : null}
          <InvestigationScanEvidence
            selectedScanId={selectedScanId}
            selectedSnapshot={selectedSnapshot}
            posture={posture}
            fixFirstView={fixFirstView}
            loadingSnapshots={loadingSnapshots}
            snapshots={snapshots}
            currentEstateId={currentEstateId}
            displayedSnapshots={displayedSnapshots}
            onSelect={selectSnapshot}
            hiddenSnapshotCount={hiddenSnapshotCount}
            showAll={showAllSnapshots}
            onToggleShowAll={() => setShowAllSnapshots((current) => !current)}
            estateMode={estateMode}
          />
        </div>

        }
        deployment={!captureMode ? <DeployGatePanel scanId={selectedScanId || undefined} /> : undefined}
        exposure={<ExposurePathLens scanId={selectedScanId || undefined} />}
      />
    </div>
  );
}

function SecurityGraphPageContent() {
  const { session } = useAuthState();
  const searchParams = useSearchParams();
  return resolveSecurityGraphSurface(searchParams) === "attack-path"
    ? <AttackPathInvestigationContent key={JSON.stringify(session)} />
    : <GraphSurface />;
}

export default function SecurityGraphPage() {
  return (
    <Suspense fallback={<div className="flex min-h-[40vh] items-center justify-center"><Loader2 className="h-8 w-8 animate-spin text-[color:var(--text-secondary)]" /></div>}>
      <SecurityGraphPageContent />
    </Suspense>
  );
}
