"use client";

import { useCallback, useEffect, useRef } from "react";
import { type Edge, type Node } from "@xyflow/react";
import { createInvestigationGraphFilters } from "@/components/lineage-filter";
import { type LineageNodeData } from "@/components/lineage-nodes";
import { isClusterPillNode } from "@/lib/sibling-aggregator";
import { type UnifiedNode } from "@/lib/graph-schema";
import { entityTypesForLayers } from "@/lib/graph-entity-mapping";
import { initialInvestigationDirection, type GraphInvestigationRequest } from "@/lib/attack-paths";
import { loadBlastInvestigation } from "@/lib/graph-blast-investigation";
import { summarizeReachability } from "@/lib/graph-reachability";
import { api } from "@/lib/api";
import type { GraphRollupContainer } from "@/lib/api-types";
import { graphResponseIsTruncated } from "@/lib/graph-truncation";
import { buildFallbackNodeData, queryResponseToGraphResponse, RELATIONSHIP_SCOPE_MAP } from "@/lib/graph-page-data";
import type { GraphPageData } from "@/hooks/use-graph-page-data";
import type { GraphCanvasModel } from "@/hooks/use-graph-canvas-model";

/** Graph page interactions: selection, search, investigations, blast radius and roll-up navigation. */
export function useGraphPageActions(page: GraphPageData & GraphCanvasModel) {
  const {
    setGraphRetry, selectedScanId, graphData, setGraphData, setLoadingGraph, setError, setSelectedNode,
    setSelectedNodeId, setSelectedRelationship, setSelectedAttackPathKey, requestedAttackPathKeyRef, searchQuery,
    setSearchQuery, setSearchResults, setSearching, investigationMode, setInvestigationMode, setReachabilitySummary,
    quietRootRef, investigationRequestId, investigationAbort, investigationDirection, setInvestigationDirection,
    setReachabilityError, setBlastRadius, setLoadingBlast, setBlastError, setRollupStack, rollupAutoDescendRef,
    setRollupDismissed, setRollupError, setRollupMapExpanded, setRollupSummaryRequested, setHoveredNodeId,
    setPinnedFocusId, setExpandedClusterIds, searchParams, filters, setFilters, requestedScanIdRef,
    requestedInvestigationRef, rollupPreferenceRef, serverEntityTypes, serverFilterKey, flowNodeDataById, displayNodes,
  } = page;
  const inspectRelationship = useCallback((edge: Edge) => {
    if (edge.data?.isClusterEdge) return;
    setSelectedNode(null); setSelectedNodeId(null);
    setSelectedRelationship(current => current?.scanId === selectedScanId && current.id === edge.id
      ? current : { scanId: selectedScanId, id: edge.id });
  }, [selectedScanId, setSelectedNode, setSelectedNodeId, setSelectedRelationship]);

  const onNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      setSelectedRelationship(null);
      // Cluster-pill click → restore the absorbed siblings in place. We
      // never open the detail panel for a synthetic cluster node.
      if (isClusterPillNode(node as Node<LineageNodeData>)) {
        // The pill disappears on expansion, so its mouse-leave may never fire.
        setHoveredNodeId(null);
        setPinnedFocusId(null);
        const id = node.id;
        setExpandedClusterIds((current) => {
          const next = new Set(current);
          next.add(id);
          return next;
        });
        return;
      }

      const data = node.data as LineageNodeData;

      setSelectedNode({
        ...data,
        attributes: {
          ...(data.attributes ?? {}),
          node_id: node.id,
        },
      });
      setSelectedNodeId(node.id);
      setSelectedAttackPathKey(null);
      // Click pin (#2257): toggle a "pinned focus" on the clicked node.
      // Re-clicking the same node clears the pin. Hover state is reset
      // because the pin replaces hover as the focus source.
      setPinnedFocusId((current) => (current === node.id ? null : node.id));
      setHoveredNodeId(null);
    },
    [setExpandedClusterIds, setHoveredNodeId, setPinnedFocusId, setSelectedAttackPathKey, setSelectedNode, setSelectedNodeId, setSelectedRelationship],
  );

  const onLargeGraphNodeSelect = useCallback(
    (nodeId: string) => {
      const node = displayNodes.find((candidate) => candidate.id === nodeId);
      if (!node) return;
      onNodeClick({} as React.MouseEvent, node);
    },
    [displayNodes, onNodeClick],
  );

  const onNodeMouseEnter = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      setHoveredNodeId(node.id);
    },
    [setHoveredNodeId],
  );

  const onNodeMouseLeave = useCallback(() => {
    setHoveredNodeId(null);
  }, [setHoveredNodeId]);

  const selectFindingCard = useCallback((id: string, data: LineageNodeData) => {
    setSelectedNode({
      ...data,
      attributes: {
        ...(data.attributes ?? {}),
        node_id: id,
      },
    });
    setSelectedNodeId(id);
    setHoveredNodeId(id);
    setSelectedAttackPathKey(null);
  }, [setHoveredNodeId, setSelectedAttackPathKey, setSelectedNode, setSelectedNodeId]);

  const runSearch = useCallback(async () => {
    const query = searchQuery.trim();
    if (!query || !selectedScanId) {
      setSearchResults([]);
      return;
    }
    setSearching(true);
    try {
      const response = await api.searchGraph(query, {
        scanId: selectedScanId,
        entityTypes: serverEntityTypes,
        ...(filters.severity ? { minSeverity: filters.severity } : {}),
        limit: 16,
      });
      setSearchResults(response.results);
    } catch {
      setSearchResults([]);
    } finally {
      setSearching(false);
    }
  }, [filters.severity, searchQuery, selectedScanId, serverEntityTypes, setSearchResults, setSearching]);

  const loadRootInvestigation = useCallback(
    async (
      request: GraphInvestigationRequest & { node?: UnifiedNode | undefined; nodeLimit?: number },
    ) => {
      if (!selectedScanId) return;
      setSelectedRelationship(null);
      const requestId = ++investigationRequestId.current;
      investigationAbort.current?.abort();
      const controller = new AbortController();
      investigationAbort.current = controller;
      const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(8000)]);
      const direction = request.direction ?? initialInvestigationDirection(request.rootId);
      const queryFilters = investigationMode?.rootId === request.rootId
        ? filters : createInvestigationGraphFilters(filters);
      if (queryFilters !== filters) {
        // This request already uses the reset scope; avoid a duplicate fetch from the filter effect.
        lastInvestigationFilterKey.current = JSON.stringify({ scanId: selectedScanId,
          entityTypes: entityTypesForLayers(queryFilters.layers), relationships: RELATIONSHIP_SCOPE_MAP[queryFilters.relationshipScope],
          runtimeMode: queryFilters.runtimeMode, maxDepth: queryFilters.maxDepth, severity: queryFilters.severity });
        setFilters(queryFilters);
      }
      setInvestigationDirection(direction);

      // Navigating to a new root opens its details once. Reloading the same root
      // (more connections, another context) leaves the drawer as the user left it.
      const quiet = investigationMode?.rootId === request.rootId;
      const fallback = request.node ? (flowNodeDataById.get(request.node.id) ?? buildFallbackNodeData(request.node)) : null;
      if (!quiet) setSelectedNode(fallback ? { ...fallback, attributes: { ...(fallback.attributes ?? {}), node_id: request.rootId } } : null);
      quietRootRef.current = quiet ? request.rootId : null;
      // The drawer's data, detail read and action target must keep one identity.
      if (!quiet) setSelectedNodeId(request.rootId);
      setPinnedFocusId(null);
      setHoveredNodeId(request.rootId);
      setSelectedAttackPathKey(null);
      setReachabilitySummary(null);
      setReachabilityError(null);
      setSearchResults([]);
      setSearchQuery(
        request.rootLabel ?? request.node?.label ?? request.rootId,
      );
      setLoadingGraph(true);
      setGraphData(current => current?.scan_id === selectedScanId ? current : null);
      setLoadingBlast(false);
      setBlastRadius(null);
      setInvestigationMode({ rootId: request.rootId, rootLabel: request.rootLabel ?? request.rootId,
        truncated: false, nodeCount: 0, edgeCount: 0 });
      try {
        const response = await api.queryGraph({
          roots: [request.rootId],
          scan_id: selectedScanId,
          direction,
          max_depth: queryFilters.maxDepth,
          max_nodes: request.nodeLimit ?? 4,
          max_edges: 96,
          timeout_ms: 2500,
          traversable_only: false,
          static_only: queryFilters.runtimeMode === "static",
          dynamic_only: queryFilters.runtimeMode === "dynamic",
          include_roots: true,
          include_attack_paths: true,
          entity_types: entityTypesForLayers(queryFilters.layers),
          relationship_types: RELATIONSHIP_SCOPE_MAP[queryFilters.relationshipScope],
        }, { signal });
        if (requestId !== investigationRequestId.current) return;
        const rootNode =
          response.nodes.find((node) => node.id === request.rootId) ??
          request.node;
        if (rootNode && !quiet) setSelectedNode(buildFallbackNodeData(rootNode));
        setGraphData(queryResponseToGraphResponse(response));
        setInvestigationMode({
          rootId: request.rootId,
          rootLabel: rootNode?.label ?? request.rootLabel ?? request.rootId,
          truncated: response.truncated,
          nodeCount: response.nodes.length,
          edgeCount: response.edges.length,
        });
        setReachabilitySummary(
          summarizeReachability({
            rootId: request.rootId,
            rootLabel: rootNode?.label ?? request.rootLabel ?? request.rootId,
            nodes: response.nodes,
            edges: response.edges,
            depthByNode: response.depth_by_node,
            direction: direction === "forward" ? "outgoing" : direction === "reverse" ? "incoming" : "both",
            includeNonTraversable: true,
            truncated: response.truncated,
          }),
        );
        setError(null);
      } catch (e) {
        if (requestId !== investigationRequestId.current) return;
        setError(
          signal.aborted ? "Graph request timed out. The previous view is retained; retry or narrow the scope." : e instanceof Error ? e.message : "Failed to load root-centered graph",
        );
      } finally {
        if (requestId === investigationRequestId.current) setLoadingGraph(false);
      }
    },
    [
      filters,
      investigationMode?.rootId,
      flowNodeDataById,
      selectedScanId, investigationAbort, investigationRequestId, quietRootRef, setBlastRadius, setError, setFilters, setGraphData, setHoveredNodeId, setInvestigationDirection, setInvestigationMode, setLoadingBlast, setLoadingGraph, setPinnedFocusId, setReachabilityError, setReachabilitySummary, setSearchQuery, setSearchResults, setSelectedAttackPathKey, setSelectedNode, setSelectedNodeId, setSelectedRelationship],
  );

  const lastInvestigationFilterKey = useRef(serverFilterKey);
  useEffect(() => {
    if (lastInvestigationFilterKey.current === serverFilterKey) return;
    lastInvestigationFilterKey.current = serverFilterKey;
    if (investigationMode) {
      void loadRootInvestigation({ rootId: investigationMode.rootId, rootLabel: investigationMode.rootLabel, direction: investigationDirection });
    }
  }, [serverFilterKey, investigationMode, investigationDirection, loadRootInvestigation]);

  useEffect(() => {
    const requested = requestedInvestigationRef.current;
    if (!requested || !selectedScanId || (requestedScanIdRef.current && requestedScanIdRef.current !== selectedScanId)) return;
    requestedInvestigationRef.current = null;
    void loadRootInvestigation(requested);
  }, [loadRootInvestigation, selectedScanId, searchParams, requestedInvestigationRef, requestedScanIdRef]);

  const focusSearchResult = useCallback(
    async (node: UnifiedNode) => {
      await loadRootInvestigation({
        rootId: node.id,
        rootLabel: node.label,
        node,
      });
    },
    [loadRootInvestigation],
  );

  const clearInvestigationMode = useCallback(() => {
    investigationRequestId.current++;
    investigationAbort.current?.abort();
    setSelectedNode(null);
    setSelectedNodeId(null);
    setLoadingGraph(false);
    setLoadingBlast(false);
    setInvestigationMode(null);
    setPinnedFocusId(null);
    setHoveredNodeId(null);
    setSelectedAttackPathKey(null);
    setReachabilitySummary(null);
    setReachabilityError(null);
    setBlastRadius(null);
    setBlastError(null);
  }, [investigationAbort, investigationRequestId, setBlastError, setBlastRadius, setHoveredNodeId, setInvestigationMode, setLoadingBlast, setLoadingGraph, setPinnedFocusId, setReachabilityError, setReachabilitySummary, setSelectedAttackPathKey, setSelectedNode, setSelectedNodeId]);

  const dismissRollup = useCallback(() => {
    rollupAutoDescendRef.current = false;
    setRollupDismissed(true);
    setRollupError(null);
  }, [rollupAutoDescendRef, setRollupDismissed, setRollupError]);

  const returnToSummary = useCallback(() => {
    rollupPreferenceRef.current = "force";
    requestedAttackPathKeyRef.current = null;
    requestedInvestigationRef.current = null;
    setSearchQuery("");
    setSearchResults([]);
    clearInvestigationMode();
    setSelectedNode(null);
    setSelectedNodeId(null);
    setRollupDismissed(false);
    setRollupMapExpanded(false);
    setRollupSummaryRequested(true);
    setRollupError(null);
  }, [clearInvestigationMode, requestedAttackPathKeyRef, requestedInvestigationRef, rollupPreferenceRef, setRollupDismissed, setRollupError, setRollupMapExpanded, setRollupSummaryRequested, setSearchQuery, setSearchResults, setSelectedNode, setSelectedNodeId]);

  const navigateRollupBreadcrumb = useCallback((index: number) => {
    rollupAutoDescendRef.current = false;
    setRollupStack((current) => current.slice(0, index + 1));
  }, [rollupAutoDescendRef, setRollupStack]);

  const resetRollupToRoot = useCallback(() => {
    rollupAutoDescendRef.current = false;
    setRollupStack([]);
  }, [rollupAutoDescendRef, setRollupStack]);

  const drillIntoRollup = useCallback((item: GraphRollupContainer) => {
    if (!item.has_children) return;
    rollupAutoDescendRef.current = false;
    setRollupSummaryRequested(true);
    setRollupMapExpanded(false);
    setRollupStack((current) => {
      if (current.at(-1)?.id === item.id) return current;
      return [...current, { id: item.id, label: item.label, cloudProvider: item.cloud_provider || undefined, cloudProviderBasis: item.cloud_provider_basis || undefined }];
    });
  }, [rollupAutoDescendRef, setRollupMapExpanded, setRollupStack, setRollupSummaryRequested]);

  const investigateRollup = useCallback(
    (item: GraphRollupContainer) => {
      void loadRootInvestigation({ rootId: item.id, rootLabel: item.label });
    },
    [loadRootInvestigation],
  );

  const loadBlastRadius = useCallback(
    async (nodeId: string, nodeLabel: string) => {
      if (!nodeId) return;
      const requestId = ++investigationRequestId.current;
      investigationAbort.current?.abort();
      const controller = new AbortController();
      investigationAbort.current = controller;
      const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(8000)]);
      // Blast radius takes over the canvas; drop any competing overlays so the
      // impacted set is the only thing highlighted.
      setSelectedAttackPathKey(null);
      setReachabilitySummary(null);
      setReachabilityError(null);
      setLoadingBlast(true);
      setLoadingGraph(false);
      setGraphData(current => current?.scan_id === selectedScanId ? current : null);
      setInvestigationMode({ rootId: nodeId, rootLabel: nodeLabel || nodeId,
        truncated: false, nodeCount: 0, edgeCount: 0 });
      setBlastError(null);
      try {
        // Impact IDs alone cannot populate a canvas that was loaded for a
        // different scope. Fetch a bounded reverse neighborhood as well.
        const { impact, context } = await loadBlastInvestigation(api, nodeId, selectedScanId || undefined, signal);
        if (requestId !== investigationRequestId.current) return;
        setGraphData(queryResponseToGraphResponse(context));
        setInvestigationMode({ rootId: nodeId, rootLabel: nodeLabel || nodeId,
          truncated: context.completeness?.complete !== true, nodeCount: context.nodes.length, edgeCount: context.edges.length });
        setBlastRadius({
          rootId: impact.node_id,
          rootLabel: nodeLabel || impact.node_id,
          nodeIds: new Set<string>([impact.node_id, ...impact.affected_nodes]),
          countsByType: impact.affected_by_type,
          affectedCount: impact.affected_count,
          maxDepthReached: impact.max_depth_reached,
          completeness: impact.completeness,
          visibleRelatedCount: context.nodes.filter(node => node.id !== impact.node_id).length,
        });
      } catch (e) {
        if (requestId !== investigationRequestId.current) return;
        setBlastRadius(null);
        setBlastError(
          signal.aborted ? "Blast radius timed out. The previous graph is retained; retry with a narrower scope." : e instanceof Error ? e.message : "Failed to compute blast radius",
        );
      } finally {
        if (requestId === investigationRequestId.current) setLoadingBlast(false);
      }
    },
    [selectedScanId, investigationAbort, investigationRequestId, setBlastError, setBlastRadius, setGraphData, setInvestigationMode, setLoadingBlast, setLoadingGraph, setReachabilityError, setReachabilitySummary, setSelectedAttackPathKey],
  );

  const retryGraph = () => {
    if (investigationMode) {
      void loadRootInvestigation({ rootId: investigationMode.rootId, rootLabel: investigationMode.rootLabel, direction: investigationDirection });
    } else {
      setGraphRetry((value) => value + 1);
    }
  };

  // The ranked selection and server traversal can independently be partial.
  // Never infer completeness from has_more alone.
  const graphTruncated = graphResponseIsTruncated(graphData);
  return {
    inspectRelationship, onNodeClick, onLargeGraphNodeSelect, onNodeMouseEnter, onNodeMouseLeave, selectFindingCard,
    runSearch, loadRootInvestigation, lastInvestigationFilterKey, focusSearchResult, clearInvestigationMode,
    dismissRollup, returnToSummary, navigateRollupBreadcrumb, resetRollupToRoot, drillIntoRollup, investigateRollup,
    loadBlastRadius, retryGraph, graphTruncated,
  };
}

export type GraphPageActions = ReturnType<typeof useGraphPageActions>;
