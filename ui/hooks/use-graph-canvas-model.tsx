"use client";

import { decodeGraphInvestigationParams } from "@/lib/attack-paths";
import { boundedGraphElements } from "@/lib/graph-neighbor-expansion";
import { declutterRelationshipLabels, hideRedundantDerivedEdges } from "@/lib/graph-label-declutter";
import { graphInvestigationContext, selectInvestigationContext, investigationRankEdges, restoreInvestigationEdges } from "@/lib/graph-investigation-context";
import { completeDirectedHopCount, visibleGraphFocus, pathRelationshipIds } from "@/lib/security-graph-focus";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { type Node } from "@xyflow/react";
import { withFindingContext } from "@/lib/finding-investigation-href";
import { ASSET_DRIFT_GRAPH_SCOPE_PARAM, createCanvasLensGraphFilters, createFocusedGraphFilters, graphScopePresetForFilters } from "@/components/lineage-filter";
import { type LineageNodeData, type LineageNodeType } from "@/components/lineage-nodes";
import { useGraphLayout } from "@/lib/use-graph-layout";
import { COMPACT_GRAPH_MIN_ZOOM, compactInvestigationLayout, readableLineageDagreLr } from "@/lib/graph-node-dimensions";
import { effectiveLodBandForGraph, useLodBand } from "@/lib/lod-renderer";
import { aggregateSiblings, EXPANDED_AGGREGATION_THRESHOLD, FOCUSED_AGGREGATION_THRESHOLD, isClusterPillNode } from "@/lib/sibling-aggregator";
import { type UnifiedNode } from "@/lib/graph-schema";
import { resolveSnapshotAttackPathCount } from "@/lib/graph-snapshot-metrics";
import { lineageNodeTypeForEntity } from "@/lib/graph-entity-mapping";
import { buildDriftIndex, diffChangeCounts, driftAttributeSummaries, countVisiblePathHops, graphNodeDisplayLabels, legendItemsForVisibleGraph, readableGraphEdges } from "@/lib/graph-utils";
import { graphFitViewOptions, graphInitialFitViewOptions, graphReadableFitViewOptions, shouldShowGraphMiniMap } from "@/lib/graph-viewport";
import { buildRollupFlowGraph } from "@/lib/graph-rollup-view";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { decideGraphRenderer } from "@/lib/graph-renderer-switch";
import { applyFilters, encodeFiltersToParams } from "@/lib/filter-algebra";
import { useGraphPresentation } from "@/hooks/use-graph-presentation";
import { graphTopologyKey, selectGraphSubgraph } from "@/lib/graph-presentation";
import { graphScenarioContextIds, graphScenarioConnectionNotes } from "@/lib/graph-scenario";
import { graphFirstFramePending } from "@/lib/graph-first-frame";
import { driftDisplayEdges, driftTally, emphasizedDisplayEdges, evidenceTally, focusDisplayNodes, lensDisplayNodes } from "@/lib/graph-display-elements";
import { getLocalNeighborhoodIds, graphErrorState } from "@/lib/graph-page-data";
import type { GraphPageData } from "@/hooks/use-graph-page-data";

/** The canvas model: flow, aggregation, layout, emphasis, camera and presentation for the loaded graph. */
export function useGraphCanvasModel(page: GraphPageData) {
  const {
    reactFlow, graphViewport, narrowViewport, canvasLayoutAspect, session, authLoading, canvasPage, setCanvasPage,
    snapshots, selectedScanId, graphData, selectedScenarioId, scenarioExpanded, scenarioState, scenarioComparison,
    attackPathQueue, attackPathQueueScanId, loadingSnapshots, error, selectedNodeDetail, graphDiff, driftLensActive,
    setDriftLensActive, driftFilter, setDriftFilter, evidenceLensActive, evidenceFilter, selectedNode, setSelectedNode,
    selectedNodeId, setSelectedNodeId, selectedRelationship, setSelectedRelationship, selectedAttackPathKey,
    requestedAttackPathKeyRef, investigationMode, reachabilitySummary, mobileGraphView, investigationDirection,
    blastRadius, rollupView, rollupStack, rollupDismissed, hoveredNodeId, setHoveredNodeId, pinnedFocusId,
    setPinnedFocusId, expandedClusterIds, setExpandedClusterIds, pathname, searchParams, filters, setFilters,
    initializedFocus, setInitializedFocus, seededFromUrlRef, requestedScanIdRef, requestedInvestigationRef,
    rollupPreferenceRef, canvasLens, canvasAgent, attackPathLens, lastSyncedUrlRef, initialContextViewRef, captureMode,
    mergedGraphData, projectedGraphData, activeSnapshot, diffPair, highlight, graphNodeById, activeScopePreset,
    selectedAttackPath, rollupNavigationActive, rollupCanvasPending, rollupCanvasFailed, rollupCanvasOwnsPresentation,
    rollupDecisionActive, rollupDisplayEdges,
  } = page;
  const flow = useMemo(() => {
    if (rollupNavigationActive && rollupView) {
      const items =
        rollupView.mode === "drilldown"
          ? (rollupView.children ?? [])
          : (rollupView.top_level ?? []);
      const rollupFlow = buildRollupFlowGraph(items, { edges: rollupDisplayEdges });
      return {
        nodes: rollupFlow.nodes,
        edges: rollupFlow.edges,
        agentNames: [] as string[],
        legend: [] as ReturnType<typeof buildUnifiedFlowGraph>["legend"],
        summary: null as
          null | ReturnType<typeof buildUnifiedFlowGraph>["summary"],
      };
    }
    if (rollupCanvasPending || rollupCanvasFailed) {
      return {
        nodes: [],
        edges: [],
        agentNames: [],
        legend: [],
        summary: null as
          null | ReturnType<typeof buildUnifiedFlowGraph>["summary"],
      };
    }
    if (!projectedGraphData) {
      return {
        nodes: [],
        edges: [],
        agentNames: [],
        legend: [],
        summary: null as
          null | ReturnType<typeof buildUnifiedFlowGraph>["summary"],
      };
    }
    const presentationFilters = selectedAttackPath
      ? (() => {
          const pathIds = new Set(selectedAttackPath.hops);
          const layers = { ...filters.layers };
          for (const node of projectedGraphData.nodes) {
            if (!pathIds.has(node.id)) continue;
            const layer = lineageNodeTypeForEntity(node.entity_type);
            if (layer) layers[layer] = true;
          }
          // A selected path is an explicit witness. Its endpoints and every
          // recorded hop must remain visible even when the previous topology
          // view used narrower severity, agent, runtime, or layer filters.
          return {
            ...filters,
            agentName: null,
            severity: null,
            vulnOnly: false,
            runtimeMode: "all" as const,
            relationshipScope: "all" as const,
            layers,
          };
        })()
      : filters;
    // A scenario can add a standalone resource or remove its last relationship.
    // Preserve those explicit changes after filtering, without inventing edges.
    const changedNodeIds = selectedScenarioId && scenarioComparison?.available && !attackPathLens
      ? graphScenarioContextIds(projectedGraphData.nodes, [], scenarioComparison.difference, [...(mergedGraphData?.edges ?? []), ...projectedGraphData.edges])
      : undefined;
    return buildUnifiedFlowGraph(projectedGraphData, presentationFilters, changedNodeIds ?? (investigationMode ? new Set([investigationMode.rootId]) : undefined));
  }, [
    projectedGraphData,
    investigationMode,
    filters,
    selectedScenarioId,
    scenarioComparison,
    attackPathLens,
    mergedGraphData?.edges,
    selectedAttackPath,
    rollupNavigationActive,
    rollupCanvasPending,
    rollupCanvasFailed,
    rollupView,
    rollupDisplayEdges,
  ]);
  const snapshotAttackPathCount = resolveSnapshotAttackPathCount({
    pageTotal: attackPathQueue?.pagination.total,
    statsTotal: graphData?.stats.attack_path_count,
    returnedPaths: flow.summary?.attackPaths ?? 0,
  });

  const queueSettled = attackPathQueueScanId === selectedScanId;
  const awaitingAutoFocus = !initializedFocus && !seededFromUrlRef.current && !investigationMode &&
    !requestedInvestigationRef.current && !rollupCanvasOwnsPresentation && !createCanvasLensGraphFilters(canvasLens, canvasAgent);
  const firstFramePending = graphFirstFramePending({
    awaitingAutoFocus, graphLoaded: Boolean(graphData), queueSettled, agentCount: flow.agentNames.length,
  });

  useEffect(() => {
    if (initializedFocus) return;
    if (flow.agentNames.length === 0) {
      // Nothing to focus: release the first frame instead of waiting forever.
      if (graphData && queueSettled) setInitializedFocus(true);
      return;
    }
    if (createCanvasLensGraphFilters(canvasLens, canvasAgent)) {
      // Canonical Canvas lenses are estate projections. Auto-picking the first
      // agent would silently collapse them into a single-agent investigation.
      setInitializedFocus(true);
      return;
    }
    if (seededFromUrlRef.current) {
      // The user landed here with an explicit URL — respect it instead of
      // overriding agentName with the first agent in the snapshot.
      setInitializedFocus(true);
      return;
    }
    setFilters(createFocusedGraphFilters(flow.agentNames[0]));
    setInitializedFocus(true);
  }, [canvasAgent, canvasLens, flow.agentNames, initializedFocus, graphData, queueSettled, seededFromUrlRef, setFilters, setInitializedFocus]);

  // Push the current filter state into the URL (replace, not push) so a
  // copied address bar reproduces the view but back/forward isn't spammed.
  useEffect(() => {
    if (typeof window === "undefined") return;
    // A destination can render before navigation commits. Writing native
    // history then would replace the origin route and interrupt the drill-in.
    if (window.location.pathname !== pathname) return;
    // Native history can move before Next commits its query snapshot. An
    // older graph render must not replace that pending navigation with its
    // own root or filters. Resume synchronization when the router catches up.
    const currentSearch = new URLSearchParams(window.location.search);
    if (currentSearch.toString() !== searchParams.toString()) return;
    const nextParams = encodeFiltersToParams(filters);
    // Client-side lens navigation can mount this surface before the snapshot
    // request resolves. Preserve the destination scan until the canonical
    // selection is available, otherwise the first URL sync silently widens a
    // pinned investigation to the newest snapshot.
    const requestedScanId =
      currentSearch.get("scan") ||
      currentSearch.get("scan_id") ||
      searchParams.get("scan") ||
      searchParams.get("scan_id") ||
      requestedScanIdRef.current;
    const shareableScanId =
      selectedScanId || (loadingSnapshots ? requestedScanId : "");
    if (shareableScanId) nextParams.set("scan", shareableScanId);
    // `lens` is composition state rather than a graph filter, so the filter
    // encoder intentionally does not own it. Keep it while syncing the rest
    // of the shareable view state.
    const lens = currentSearch.get("lens") || searchParams.get("lens");
    if (lens) nextParams.set("lens", lens);
    const contextView = currentSearch.get("context_view") || initialContextViewRef.current
      || (activeSnapshot?.snapshot_kind === "correlation" ? "dependency" : null);
    if (contextView) nextParams.set("context_view", contextView);
    if (selectedScenarioId) {
      nextParams.set("scenario", selectedScenarioId);
      nextParams.set("state", attackPathLens ? "current" : scenarioState);
    }
    if (captureMode) {
      nextParams.set("capture", "1");
    }
    const shareableInvestigation =
      requestedInvestigationRef.current ?? investigationMode;
    if (shareableInvestigation) {
      nextParams.set("investigate", "1");
      nextParams.set("root", shareableInvestigation.rootId);
      nextParams.set("direction", requestedInvestigationRef.current?.direction ?? investigationDirection);
      // Response labels are presentation data. Writing them back after a fetch
      // can enqueue a stale router restore over a newer root navigation.
      const urlInvestigation = decodeGraphInvestigationParams(currentSearch);
      const requestedLabel = requestedInvestigationRef.current?.rootLabel ??
        (urlInvestigation?.rootId === shareableInvestigation.rootId ? urlInvestigation.rootLabel : undefined);
      if (requestedLabel && requestedLabel !== shareableInvestigation.rootId) nextParams.set("q", requestedLabel);
    }
    const shareablePath = selectedAttackPathKey ?? requestedAttackPathKeyRef.current;
    if (shareablePath) nextParams.set("path", shareablePath);
    if (activeScopePreset === "assetDrift") {
      nextParams.set("scope", ASSET_DRIFT_GRAPH_SCOPE_PARAM);
    }
    if (rollupDismissed) {
      nextParams.set("rollup", "0");
      nextParams.delete("rollup_node");
    } else if (rollupNavigationActive || rollupPreferenceRef.current === "force") {
      nextParams.set("rollup", "1");
      const drillNode = rollupStack.at(-1)?.id;
      if (drillNode) {
        nextParams.set("rollup_node", drillNode);
      } else {
        nextParams.delete("rollup_node");
      }
    } else {
      nextParams.delete("rollup");
      nextParams.delete("rollup_node");
    }
    const next = nextParams.toString();
    const url = withFindingContext(next ? `${pathname}?${next}` : pathname, currentSearch);
    // Filters are client state. Synchronize their shareable URL without an
    // App Router navigation/server-component request on every interaction.
    // Next integrates native history updates with useSearchParams.
    if (lastSyncedUrlRef.current === url) return;
    lastSyncedUrlRef.current = url;
    if (url === `${pathname}${window.location.search}`) return;
    history.replaceState(null, "", url);
  }, [
    activeScopePreset,
    activeSnapshot?.snapshot_kind,
    attackPathLens,
    captureMode,
    filters,
    investigationMode,
    investigationDirection,
    loadingSnapshots,
    pathname,
    rollupDismissed,
    rollupNavigationActive,
    rollupStack,
    searchParams,
    selectedAttackPathKey,
    selectedScanId,
    selectedScenarioId,
    scenarioState, initialContextViewRef, lastSyncedUrlRef, requestedAttackPathKeyRef, requestedInvestigationRef, requestedScanIdRef, rollupPreferenceRef]);

  // Constraint propagation — recompute valid values whenever graph or
  // filters change. Cheap on focused snapshots, BFS-bounded on expanded.
  const filterAlgebra = useMemo(
    () => applyFilters(projectedGraphData, filters),
    [projectedGraphData, filters],
  );
  const validValues = filterAlgebra.validValues;

  const handleResetFilters = useCallback(() => {
    setFilters(
      createCanvasLensGraphFilters(canvasLens, canvasAgent) ??
        createFocusedGraphFilters(flow.agentNames[0] ?? null),
    );
  }, [canvasAgent, canvasLens, flow.agentNames, setFilters]);

  const flowNodeById = useMemo(() => new Map(flow.nodes.map((node) => [node.id, node])), [flow.nodes]);
  const flowNodeDataById = useMemo(() => new Map(flow.nodes.map((node) => [node.id, node.data])), [flow.nodes]);
  const attackPathNodeIds = useMemo(
    () => (selectedAttackPath ? new Set(selectedAttackPath.hops) : null),
    [selectedAttackPath],
  );

  // Sibling aggregation (#2257). Threshold tracks the active filter
  // preset — operator triage (focused) collapses faster than topology
  // review (expanded). Run before layout so the layout engine never positions
  // siblings that the cluster pill is going to hide.
  // An investigation canvas is bounded: a fan of five or more siblings reads as one
  // expandable group instead of a column too tall to read at its fitted zoom.
  const aggregationThreshold = selectedAttackPath
    ? Number.MAX_SAFE_INTEGER
    : filters.vulnOnly || investigationMode
      ? FOCUSED_AGGREGATION_THRESHOLD
      : EXPANDED_AGGREGATION_THRESHOLD;

  const aggregated = useMemo(
    () => {
      if (rollupNavigationActive) {
        return {
          nodes: flow.nodes,
          edges: flow.edges,
          clusters: new Map<
            string,
            {
              parentId: string;
              childType: LineageNodeType;
              members: string[];
            }
          >(),
        };
      }
      return aggregateSiblings(flow.nodes, flow.edges, {
        thresholdN: aggregationThreshold,
        expandedClusterIds: expandedClusterIds,
      });
    },
    [
      flow.nodes,
      flow.edges,
      aggregationThreshold,
      expandedClusterIds,
      rollupNavigationActive,
    ],
  );
  const aggregatedClusterNodes = useMemo(
    () =>
      aggregated.nodes.filter((node) =>
        isClusterPillNode(node as Node<LineageNodeData>),
      ),
    [aggregated.nodes],
  );
  const graphIdentityKey = useMemo(
    () =>
      JSON.stringify({
        nodes: flow.nodes.map((node) => node.id),
        edges: flow.edges.map(
          (edge) => `${edge.source}->${edge.target}:${edge.id}`,
        ),
      }),
    [flow.nodes, flow.edges],
  );

  useEffect(() => {
    setExpandedClusterIds(new Set());
    setCanvasPage(0);
    setPinnedFocusId(null);
    setHoveredNodeId(null);
  }, [graphIdentityKey, setCanvasPage, setExpandedClusterIds, setHoveredNodeId, setPinnedFocusId]);

  // The unified security graph is DAG-shaped (provider/identity → agent →
  // server → tool/package → finding, and user → role → resource). A
  // left-to-right hierarchical layout reads as blast-radius flow and never
  // overlaps nodes; the force layout piled siblings on top of each other on
  // the broad estate view. Large graphs switch to the WebGL/overview
  // renderers upstream, so ReactFlow only ever lays out small/medium graphs
  // where dagre is the better fit.
  const compactGroupedTopology = aggregated.clusters.size > 0 && aggregated.nodes.length <= 6;
  const compactMobileTopology = narrowViewport && !selectedAttackPath &&
    !rollupNavigationActive && compactGroupedTopology;
  const graphLayoutKind = compactMobileTopology && !investigationMode ? "dagre" : selectedAttackPath || selectedScenarioId || rollupNavigationActive || investigationMode ? "dagre-lr" : "asset-hierarchy";
  // "Show more" reads against the root's recorded degree, when the detail read was complete.
  const rootConnections = useMemo(() => {
    const detail = selectedNodeDetail?.response;
    if (!investigationMode || detail?.node?.id !== investigationMode.rootId || detail.completeness?.complete === false) return null;
    const total = new Set([...(detail.edges_out ?? []).map(edge => edge.target), ...(detail.edges_in ?? []).map(edge => edge.source)]).size;
    const loaded = new Set((graphData?.edges ?? []).flatMap(edge => edge.source === investigationMode.rootId ? [edge.target] : edge.target === investigationMode.rootId ? [edge.source] : [])).size;
    return total > loaded ? { loaded, total } : null;
  }, [selectedNodeDetail, investigationMode, graphData]);
  const scenarioContextIds = useMemo(() => {
    if (!selectedScenarioId || !scenarioComparison?.available || scenarioExpanded || attackPathLens || selectedAttackPath || investigationMode) return undefined;
    return graphScenarioContextIds(aggregated.nodes, aggregated.edges, scenarioComparison.difference, mergedGraphData?.edges);
  }, [selectedScenarioId, scenarioComparison, scenarioExpanded, attackPathLens, selectedAttackPath, investigationMode, aggregated.nodes, aggregated.edges, mergedGraphData?.edges]);
  const scenarioConnectionNotes = useMemo(() => scenarioState === "proposed" && scenarioComparison?.available
    ? graphScenarioConnectionNotes(scenarioComparison.proposed.nodes.map(node => node.id), scenarioComparison.proposed.edges,
      mergedGraphData?.edges ?? [], scenarioComparison.difference.edges_removed)
    : new Map<string, string>(), [scenarioState, scenarioComparison, mergedGraphData]);
  const scenarioElements = useMemo(() => {
    const selected = selectGraphSubgraph(aggregated.nodes, aggregated.edges, attackPathNodeIds ?? scenarioContextIds);
    // Use the full proposal to distinguish missing connections from neighbors
    // merely hidden by the active scope. Never remove an endpoint of a visible edge.
    const connected = new Set(selected.edges.flatMap(edge => [edge.source, edge.target]));
    const unconnected = selected.nodes.filter(node => scenarioConnectionNotes.has(node.id) && !connected.has(node.id));
    const ids = new Set(unconnected.map(node => node.id));
    return { ...selected, nodes: selected.nodes.filter(node => !ids.has(node.id)), unconnected };
  }, [aggregated.nodes, aggregated.edges, attackPathNodeIds, scenarioContextIds, scenarioConnectionNotes]);
  const investigationContext = useMemo(() => graphInvestigationContext(scenarioElements.nodes, scenarioElements.edges, {
    rootId: investigationMode?.rootId,
    correlation: activeSnapshot?.snapshot_kind === "correlation",
    pathSelected: Boolean(selectedAttackPath || selectedScenarioId || rollupNavigationActive),
  }), [scenarioElements, investigationMode?.rootId, activeSnapshot?.snapshot_kind, selectedAttackPath, selectedScenarioId, rollupNavigationActive]);
  // A short investigation should fit as readable cards, not tiny summary pills
  // separated by the spacing intended for a much larger estate.
  const investigationLayout = compactInvestigationLayout(Boolean(investigationMode) || (!rollupNavigationActive && flow.nodes.length <= 16), aggregated.nodes.length, Boolean(investigationContext));
  const compactInvestigationTopology = investigationLayout !== undefined;
  const requestedContextGroup = searchParams.get("context_view");
  const selectedContextGroup = investigationContext?.groups.some(group => group.id === requestedContextGroup)
    ? requestedContextGroup!
    : requestedContextGroup === "all" || investigationContext?.anchorId || initialContextViewRef.current === "all" ? "all" : "dependency";
  const contextElements = useMemo(() => {
    const selected = investigationContext
      ? { ...scenarioElements, ...selectInvestigationContext(investigationContext, selectedContextGroup) }
      : { ...scenarioElements, omittedNodes: 0, crossContextEdges: 0 };
    // A derived shares_* link restates a shared resource the investigation already draws.
    return investigationMode ? { ...selected, edges: hideRedundantDerivedEdges(selected.edges, selected.nodes, mergedGraphData?.edges) } : selected;
  }, [scenarioElements, investigationContext, selectedContextGroup, investigationMode, mergedGraphData?.edges]);
  const selectContextGroup = useCallback((id: string) => {
    setCanvasPage(0);
    if (investigationContext && selectedNodeId && !selectInvestigationContext(investigationContext, id).nodes.some(node => node.id === selectedNodeId)) {
      setSelectedNodeId(null);
      setSelectedNode(null);
      setPinnedFocusId(null);
      setHoveredNodeId(null);
    }
    setSelectedRelationship(null);
    const url = new URL(window.location.href);
    url.searchParams.set("context_view", id);
    history.replaceState(null, "", url);
  }, [investigationContext, selectedNodeId, setCanvasPage, setHoveredNodeId, setPinnedFocusId, setSelectedNode, setSelectedNodeId, setSelectedRelationship]);
  const layoutInput = useMemo(() => {
    const selected = contextElements;
    // Decide broad-map rendering before paging the focused React Flow canvas.
    // Otherwise the 100-node page can never reach the WebGL threshold.
    const broadMap = !investigationMode && !scenarioContextIds && decideGraphRenderer({
      nodeCount: selected.nodes.length, edgeCount: selected.edges.length,
      captureMode, selectedAttackPath: Boolean(selectedAttackPath), rollupActive: rollupNavigationActive,
      graphOnlyFindings: selected.nodes.every(node => ["vulnerability", "misconfiguration"].includes(node.data.nodeType)),
    }).kind === "webgl";
    if (broadMap) return { ...selected, omittedNodes: 0, pageCount: 1, page: 0, layoutRequired: false };
    return { ...boundedGraphElements(selected.nodes, selected.edges, [...(attackPathNodeIds ?? scenarioContextIds ?? [])], canvasPage), layoutRequired: true };
  }, [contextElements, attackPathNodeIds, scenarioContextIds, canvasPage, investigationMode, captureMode, selectedAttackPath, rollupNavigationActive]);
  const rankedInvestigationEdges = useMemo(() => investigationContext ? investigationRankEdges(investigationContext, layoutInput.edges) : layoutInput.edges,
    [investigationContext, layoutInput.edges]);
  const { nodes: layoutNodes, edges: rankedLayoutEdges, pending: layoutPending } = useGraphLayout(
    graphLayoutKind,
    layoutInput.nodes,
    rankedInvestigationEdges,
    {
      dagre: { direction: "TB", nodeWidth: 240, nodeHeight: 216, rankSep: 32, nodeSep: 24 },
      force: {
        idealEdgeLength: filters.agentName ? 168 : 196,
        nodeRepulsion: filters.agentName ? 3600 : 4400,
        preservePinnedPositions: true,
      },
      // Reserve the circular glyph, wrapped label and evidence metadata.
      dagreLr: readableLineageDagreLr(
        selectedAttackPath
          ? { rankSep: 72, nodeSep: 40, nodeWidth: 240, nodeHeight: 224, fitAspect: 2.65 }
          : selectedScenarioId
            ? { rankSep: 112, nodeSep: 12, nodeWidth: 240, nodeHeight: 208, minSeparation: { width: 240, height: 208, gap: 24 } }
          : compactInvestigationTopology
            ? { ...investigationLayout, fitAspect: canvasLayoutAspect, wrapRanks: false }
            : filters.agentName
              ? { rankSep: 152, nodeSep: 52 }
              : {},
      ),
    },
    layoutInput.layoutRequired && !rollupDecisionActive && !rollupCanvasPending && !rollupCanvasFailed,
  );
  const layoutEdges = useMemo(() => restoreInvestigationEdges(layoutInput.edges, rankedLayoutEdges, graphLayoutKind === "dagre"),
    [layoutInput.edges, rankedLayoutEdges, graphLayoutKind]);
  const selectedEvidenceHopCount = selectedAttackPath
    ? Math.max(0, selectedAttackPath.hops.length - 1)
    : 0;
  const selectedVisibleHopCount = selectedAttackPath
    ? countVisiblePathHops(
        selectedAttackPath.hops,
        layoutNodes.map((node) => node.id),
      )
    : 0;
  const selectedPathDecision = useMemo(() => {
    if (!selectedAttackPath) return null;
    const nodes = selectedAttackPath.hops
      .map((id) => graphNodeById.get(id))
      .filter((node): node is UnifiedNode => Boolean(node));
    const finding = nodes.find((node) =>
      ["vulnerability", "misconfiguration"].includes(String(node.entity_type)),
    );
    const packageNode = nodes.find((node) => String(node.entity_type) === "package");
    const fixedVersion = typeof finding?.attributes?.fixed_version === "string"
      ? finding.attributes.fixed_version
      : null;
    const packageName = packageNode?.label.split("@")[0] || "affected package";
    const directedTraversable = completeDirectedHopCount(selectedAttackPath);
    const findingLabel = finding?.label ?? selectedAttackPath.vuln_ids[0] ?? "finding";
    return {
      findingLabel,
      nextAction: fixedVersion
        ? `Upgrade ${packageName} to ${fixedVersion}`
        : `Review and remediate ${findingLabel}`,
      remediationHref: `/remediation?scan=${encodeURIComponent(selectedScanId)}&cve=${encodeURIComponent(findingLabel)}`,
      directedTraversable,
      hasHopReceipts: Boolean(selectedAttackPath.hop_evidence?.length),
      sourceLabel: nodes[0]?.label ?? selectedAttackPath.source,
      targetLabel: nodes.at(-1)?.label ?? selectedAttackPath.target,
    };
  }, [graphNodeById, selectedAttackPath, selectedScanId]);

  // Focus mode (#2257). The "active" focus is whichever the operator
  // pinned (click) — falling back to whatever is hovered. Pinning
  // survives until the operator clicks the empty pane or pins another
  // node. Hover never overrides a pin.
  const lineageLayoutNodes = layoutNodes as Node<LineageNodeData>[];
  const canvasLayoutNodes = rollupNavigationActive
    ? (aggregated.nodes as Node<LineageNodeData>[])
    : lineageLayoutNodes;
  const requestedFocusId = pinnedFocusId ?? hoveredNodeId;
  const activeFocusId = visibleGraphFocus(canvasLayoutNodes, requestedFocusId);
  const localNeighborhoodIds = useMemo(
    () =>
      activeFocusId
        ? getLocalNeighborhoodIds(activeFocusId, layoutEdges)
        : null,
    [activeFocusId, layoutEdges],
  );

  const attackPathEdgeIds = useMemo(
    () =>
      selectedAttackPath ? pathRelationshipIds(layoutEdges, selectedAttackPath) : null,
    [selectedAttackPath, layoutEdges],
  );
  const attackPathNodeOrder = useMemo(
    () =>
      selectedAttackPath
        ? new Map(selectedAttackPath.hops.map((hop, index) => [hop, index]))
        : null,
    [selectedAttackPath],
  );

  // Levels of detail: the zoom band keeps dense graphs readable without moving nodes.
  const lodBand = useLodBand();
  const effectiveLodBand = compactInvestigationTopology || compactGroupedTopology || (scenarioContextIds && scenarioContextIds.size <= 8) ? "detail" : effectiveLodBandForGraph(lodBand, {
    sourceNodeCount: flow.nodes.length,
    renderedNodeCount: aggregated.nodes.length,
    clusterCount: aggregated.clusters.size,
    rollupActive: rollupNavigationActive,
  });
  const baseDisplayNodes = useMemo(() => focusDisplayNodes({
    nodes: canvasLayoutNodes, band: effectiveLodBand, blastRadius, pathNodeIds: attackPathNodeIds, pathOrder: attackPathNodeOrder,
    reachability: reachabilitySummary, neighborhood: localNeighborhoodIds, focusId: activeFocusId,
  }), [canvasLayoutNodes, localNeighborhoodIds, attackPathNodeIds, attackPathNodeOrder, reachabilitySummary, blastRadius, activeFocusId, effectiveLodBand]);

  // Drift lens: inert unless a diff exists and the operator armed it. Estate
  // highlights merge per-source diffs; an explicit snapshot pair always wins.
  const lensDiff = graphDiff ?? (diffPair ? null : highlight.diff);
  const [driftIndex, diffCounts] = useMemo(() => [buildDriftIndex(lensDiff), diffChangeCounts(graphDiff)] as const, [lensDiff, graphDiff]);
  const driftAttributeSummaryList = useMemo(() => driftAttributeSummaries(driftIndex), [driftIndex]);
  const driftLensEngaged = driftLensActive && Boolean(lensDiff) && driftIndex.hasChanges;
  // A snapshot with no older baseline disarms the lens so it never lingers as a stale overlay.
  useEffect(() => {
    if (!lensDiff) {
      setDriftLensActive(false);
      setDriftFilter("all");
    }
  }, [lensDiff, setDriftFilter, setDriftLensActive]);
  const displayNodes = useMemo(() => lensDisplayNodes({
    nodes: baseDisplayNodes, driftEngaged: driftLensEngaged, driftIndex, driftFilter, evidenceActive: evidenceLensActive, evidenceFilter,
  }), [baseDisplayNodes, driftIndex, driftLensEngaged, driftFilter, evidenceLensActive, evidenceFilter]);
  const drift = useMemo(() => driftTally(baseDisplayNodes, driftIndex), [baseDisplayNodes, driftIndex]);
  const evidenceCounts = useMemo(() => evidenceTally(baseDisplayNodes), [baseDisplayNodes]);
  const compressedGroupCount = aggregatedClusterNodes.length;
  const renderedNodeCount = displayNodes.length;

  const baseDisplayEdges = useMemo(() => emphasizedDisplayEdges({
    edges: layoutEdges, nodes: displayNodes, neighborhood: localNeighborhoodIds, pathEdgeIds: attackPathEdgeIds,
    blastRadius, reachability: reachabilitySummary, captureMode, zoom: graphViewport.zoom,
  }), [layoutEdges, localNeighborhoodIds, attackPathEdgeIds, reachabilitySummary, blastRadius, captureMode, graphViewport.zoom, displayNodes]);
  const accessibleBaseDisplayEdges = useMemo(
    () => declutterRelationshipLabels(readableGraphEdges(baseDisplayEdges.map(edge => ({ ...edge, selected: selectedRelationship?.scanId === selectedScanId && selectedRelationship.id === edge.id,
      // A phone shows a relationship's caption only on selection; the list view names every one.
      ...(narrowViewport && !edge.data?.isClusterEdge && !edge.data?.aggregate ? { label: undefined, data: { ...edge.data, quietLabel: true } } : {}) })), undefined, {
      captureMode,
      zoom: graphViewport.zoom,
      nodeLabels: graphNodeDisplayLabels(displayNodes),
      preserveVisualStyle: true,
      preserveLabelState: true,
    })),
    [baseDisplayEdges, captureMode, displayNodes, graphViewport.zoom, selectedRelationship, selectedScanId, narrowViewport],
  );
  const displayEdges = useMemo(() => driftDisplayEdges(accessibleBaseDisplayEdges, driftLensEngaged, driftIndex), [accessibleBaseDisplayEdges, driftLensEngaged, driftIndex]);

  const legendItems = useMemo(
    () => legendItemsForVisibleGraph(displayNodes, displayEdges),
    [displayEdges, displayNodes],
  );
  const viewportOptions = useMemo(
    () => {
      const options = graphFitViewOptions({
        nodeCount: displayNodes.length,
        edgeCount: displayEdges.length,
        selectedNode: false,
        mode: "lineage",
        captureMode,
      });
      return rollupNavigationActive ? { ...options, maxZoom: 1 } : options;
    },
    [captureMode, displayEdges.length, displayNodes.length, rollupNavigationActive],
  );
  const [manualCameraScope, setManualCameraScope] = useState<string | null>(null);
  const cameraScope = JSON.stringify([selectedScanId, filters, selectedNodeId, selectedRelationship?.id, selectedAttackPathKey, investigationMode?.rootId, selectedContextGroup, investigationContext ? displayNodes.map(node => node.id) : null]);
  const manualCamera = manualCameraScope === cameraScope;
  const initialViewportRequest = useMemo<ReturnType<typeof graphInitialFitViewOptions>>(() => {
    if (!narrowViewport && compactInvestigationTopology) return { ...viewportOptions, minZoom: COMPACT_GRAPH_MIN_ZOOM, maxZoom: 1 };
    if (scenarioExpanded || scenarioContextIds || (investigationMode && displayNodes.length <= 8)) return { ...viewportOptions, maxZoom: 1 };
    // Whole-estate navigation starts with all returned scopes in frame.
    // A selected finding or proposed change keeps its explicit close-up.
    if ((canvasLens === "estate" && displayNodes.length <= 6 && !selectedNodeId && !selectedAttackPath && !investigationMode && scenarioState === "current")) return viewportOptions;
    const difference = scenarioState !== "current" ? scenarioComparison?.difference : undefined;
    const proposedIds = [...(difference?.nodes_added ?? []), ...(difference?.nodes_changed ?? [])]
      .flatMap((item): string[] => {
        if (typeof item === "string") return [item];
        if (!item || typeof item !== "object") return [];
        const id = "node_id" in item ? item.node_id : "id" in item ? item.id : null;
        return typeof id === "string" ? [id] : [];
      });
    return graphInitialFitViewOptions(displayNodes, viewportOptions, selectedNodeId, proposedIds);
  }, [canvasLens, displayNodes, viewportOptions, selectedNodeId, selectedAttackPath, investigationMode, scenarioState, scenarioComparison, scenarioExpanded, scenarioContextIds, narrowViewport, compactInvestigationTopology]);
  const initialAnchorId = initialViewportRequest.nodes?.[0]?.id;
  // React Flow shares this prop with its queued imperative fit operation.
  // Hover/LOD node objects must not overwrite a user's pending Fit all request
  // with an equivalent-but-new initial anchor options object.
  const initialViewportOptions = useMemo<ReturnType<typeof graphInitialFitViewOptions>>(
    () => {
      const options = initialAnchorId
        ? graphInitialFitViewOptions([{ id: initialAnchorId, data: {} }], viewportOptions, initialAnchorId)
        : viewportOptions;
      // Scenario views share width with the decision panel and app navigation.
      // Allow the complete proposed context to fit shorter desktop canvases.
      if (selectedScenarioId) return { ...options, padding: Math.max(0.2, options.padding), minZoom: 0.05, maxZoom: 1 };
      if (compactInvestigationTopology && !narrowViewport) return { ...options, minZoom: 0.05, maxZoom: displayNodes.length <= 6 ? 1.25 : 1 };
      return rollupNavigationActive ? { ...viewportOptions, minZoom: 0.05, maxZoom: 1 } : selectedScenarioId && !scenarioExpanded ? { ...options, minZoom: 0.75, maxZoom: 1 } : options;
    },
    [initialAnchorId, viewportOptions, selectedScenarioId, scenarioExpanded, compactInvestigationTopology, narrowViewport, displayNodes.length, rollupNavigationActive],
  );
  const showMiniMap = useMemo(
    () =>
      !captureMode &&
      shouldShowGraphMiniMap({
        nodeCount: displayNodes.length,
        edgeCount: displayEdges.length,
        selectedNode: Boolean(selectedNode),
        mode: "lineage",
      }),
    [captureMode, displayEdges.length, displayNodes.length, selectedNode],
  );
  const presentationScope = useMemo(
    () => ({
      tenantId: session?.tenant_id || "local",
      subject: session?.subject || session?.auth_method || "local-viewer",
      snapshotId: selectedScanId || "unselected",
      lens: selectedAttackPath ? "investigation" : "lineage",
      scope: JSON.stringify({
        preset: graphScopePresetForFilters(filters),
        agent: filters.agentName,
        severity: filters.severity,
        path: selectedAttackPathKey,
        root: investigationMode?.rootId ?? null,
        context: investigationContext ? selectedContextGroup : null,
        rollup: rollupStack.at(-1)?.id ?? null,
        topology: graphTopologyKey(displayNodes, displayEdges),
      }),
    }),
    [displayEdges, displayNodes, filters, investigationMode?.rootId, investigationContext, selectedContextGroup, rollupStack, selectedAttackPath, selectedAttackPathKey, selectedScanId, session?.auth_method, session?.subject, session?.tenant_id],
  );
  const presentation = useGraphPresentation({
    nodes: displayNodes,
    scope: presentationScope,
    // Keep the saved-layout identity stable across the responsive default.
    // Explicit personal positions and viewport remain authoritative on resize.
    layout: graphLayoutKind === "asset-hierarchy" ? "evidence-flow-v1" : "dagre-lr",
    enabled: !captureMode && !authLoading && Boolean(session),
    ownerActive: Boolean(session),
    localMode: session?.recommended_ui_mode === "no_auth",
  });
  const fitGeneration = useRef(0);
  useEffect(() => () => { fitGeneration.current += 1; }, [cameraScope]);
  const fitVisible = useCallback(() => {
    setManualCameraScope(cameraScope);
    const generation = ++fitGeneration.current;
    const options = { ...viewportOptions, padding: Math.max(investigationContext ? 0.25 : 0.2, viewportOptions.padding) };
    const fit = () => {
      if (fitGeneration.current !== generation) return;
      void reactFlow.fitView({ ...options, duration: 240 }).then(() => {
        if (!investigationContext) return;
        // Caption sizes change with zoom. Include their final measured extent,
        // but abandon the settling pass after a scope change or user movement.
        requestAnimationFrame(() => requestAnimationFrame(() => {
          if (fitGeneration.current === generation) void reactFlow.fitView({ ...options, duration: 0 });
        }));
      });
    };
    // Let React Flow apply manual-camera props before enqueueing the fit;
    // changing its fitView prop otherwise clears the pending imperative fit.
    requestAnimationFrame(() => requestAnimationFrame(fit));
  }, [reactFlow, viewportOptions, investigationContext, cameraScope]);
  const fitSelection = useCallback(async () => {
    if (rollupNavigationActive) {
      await reactFlow.fitView({ ...viewportOptions, minZoom: 0.16, maxZoom: 1, padding: 0.04 });
      return;
    }
    const framing = graphReadableFitViewOptions(displayNodes, viewportOptions, selectedNodeId ?? investigationMode?.rootId);
    if (!framing.nodes?.length) return;
    await reactFlow.fitView(framing);
    const canvas = document.querySelector(".react-flow");
    const drawer = document.querySelector('[data-testid="graph-entity-drawer"]');
    const drawerWidth = drawer?.getBoundingClientRect().width ?? 0;
    if (canvas && drawer && drawer.getBoundingClientRect().left < canvas.getBoundingClientRect().right && drawerWidth < canvas.getBoundingClientRect().width) {
      const viewport = reactFlow.getViewport();
      void reactFlow.setViewport({ ...viewport, x: viewport.x - drawerWidth / 2 });
    }
  }, [displayNodes, investigationMode?.rootId, reactFlow, rollupNavigationActive, selectedNodeId, viewportOptions]);

  const compactLayoutKey = layoutNodes.map(node => `${node.id}:${node.position.x}:${node.position.y}`).join("|");

  const autoLayout = useCallback(() => {
    presentation.autoLayout();
    window.setTimeout(fitVisible, 0);
  }, [fitVisible, presentation]);
  const resetLayout = useCallback(() => {
    presentation.reset();
    window.setTimeout(fitVisible, 0);
  }, [fitVisible, presentation]);
  // The list hides the canvas, so it was measured at zero size; fit once it is shown.
  useEffect(() => {
    if (!narrowViewport || !investigationMode || mobileGraphView !== "graph") return;
    const frame = requestAnimationFrame(() => fitVisible());
    return () => cancelAnimationFrame(frame);
    // Fit on the switch itself, not on every later camera or data change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mobileGraphView]);
  const relationshipEvidenceCount = useMemo(
    () =>
      graphData?.edges.filter(
        (edge) => Object.keys(edge.evidence ?? {}).length > 0,
      ).length ?? null,
    [graphData],
  );

  const hasContextualGraph = useMemo(
    () =>
      displayNodes.some((node) => {
        const nodeType = (node.data as LineageNodeData).nodeType;
        return nodeType !== "vulnerability" && nodeType !== "misconfiguration";
      }),
    [displayNodes],
  );

  const graphOnlyFindings = displayNodes.length > 0 && !hasContextualGraph;
  const graphRenderer = decideGraphRenderer({
    nodeCount: renderedNodeCount,
    edgeCount: displayEdges.length,
    captureMode,
    selectedAttackPath: Boolean(selectedAttackPath),
    reachabilityActive: Boolean(reachabilitySummary),
    rollupActive: rollupNavigationActive,
    graphOnlyFindings,
  });
  const showViewportScope = !rollupDecisionActive && Boolean(rollupNavigationActive || selectedScenarioId || investigationMode || initialViewportOptions.nodes || displayNodes.length > 6) && graphRenderer.kind === "react-flow";
  const showScopeEvidence = !rollupNavigationActive && !rollupDecisionActive && displayNodes.length > 0;
  const showContextControls = Boolean(investigationContext) && graphRenderer.kind === "react-flow";
  // A phone reads the loaded graph as a list first (paths, or a root's connections);
  // the fitted canvas is one tap away. A focused attack path has its own column.
  const mobileListAvailable = narrowViewport && displayNodes.length > 0 && graphRenderer.kind === "react-flow" && !graphOnlyFindings &&
    !selectedAttackPath && !selectedScenarioId && !rollupNavigationActive && !rollupDecisionActive && !firstFramePending;
  const mobileListActive = mobileListAvailable && mobileGraphView === "list";
  const showChangesEntry = Boolean(selectedScanId) && !selectedScenarioId;
  const showLegend = !mobileListActive && !rollupNavigationActive && !rollupDecisionActive && graphRenderer.kind === "react-flow" && displayNodes.length > 0;

  // Soft re-frame when drift/evidence lenses engage so ring emphasis stays in view.
  useEffect(() => {
    if (graphRenderer.kind !== "react-flow") return;
    if (!driftLensActive && !evidenceLensActive) return;
    const timer = window.setTimeout(() => {
      void reactFlow.fitView({ ...viewportOptions, duration: 280 });
    }, 80);
    return () => window.clearTimeout(timer);
  }, [
    driftLensActive,
    evidenceLensActive,
    driftFilter,
    evidenceFilter,
    graphRenderer.kind,
    reactFlow,
    viewportOptions,
  ]);

  const graphPanelError =
    error && snapshots.length > 0 ? graphErrorState(error) : null;
  const findingNodes = useMemo(
    () =>
      displayNodes
        .filter((node) => {
          const nodeType = (node.data as LineageNodeData).nodeType;
          return (
            nodeType === "vulnerability" || nodeType === "misconfiguration"
          );
        })
        .map((node) => ({ id: node.id, data: node.data as LineageNodeData })),
    [displayNodes],
  );

  return {
    flow, snapshotAttackPathCount, queueSettled, awaitingAutoFocus, firstFramePending, filterAlgebra, validValues,
    handleResetFilters, flowNodeById, flowNodeDataById, attackPathNodeIds, aggregationThreshold, aggregated,
    aggregatedClusterNodes, graphIdentityKey, compactGroupedTopology, compactMobileTopology, graphLayoutKind,
    rootConnections, scenarioContextIds, scenarioConnectionNotes, scenarioElements, investigationContext,
    investigationLayout, compactInvestigationTopology, requestedContextGroup, selectedContextGroup, contextElements,
    selectContextGroup, layoutInput, rankedInvestigationEdges, layoutNodes, rankedLayoutEdges, layoutPending,
    layoutEdges, selectedEvidenceHopCount, selectedVisibleHopCount, selectedPathDecision, lineageLayoutNodes,
    canvasLayoutNodes, requestedFocusId, activeFocusId, localNeighborhoodIds, attackPathEdgeIds, attackPathNodeOrder,
    lodBand, effectiveLodBand, baseDisplayNodes, lensDiff, driftIndex, diffCounts, driftAttributeSummaryList,
    driftLensEngaged, displayNodes, drift, evidenceCounts, compressedGroupCount, renderedNodeCount, baseDisplayEdges,
    accessibleBaseDisplayEdges, displayEdges, legendItems, viewportOptions, manualCameraScope, setManualCameraScope,
    cameraScope, manualCamera, initialViewportRequest, initialAnchorId, initialViewportOptions, showMiniMap,
    presentationScope, presentation, fitGeneration, fitVisible, fitSelection, compactLayoutKey, autoLayout,
    resetLayout, relationshipEvidenceCount, hasContextualGraph, graphOnlyFindings, graphRenderer, showViewportScope,
    showScopeEvidence, showContextControls, mobileListAvailable, mobileListActive, showChangesEntry, showLegend,
    graphPanelError, findingNodes,
  };
}

export type GraphCanvasModel = ReturnType<typeof useGraphCanvasModel>;
