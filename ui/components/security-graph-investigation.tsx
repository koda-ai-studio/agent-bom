"use client";

import { activateGraphNodeFromKeyboard } from "@/lib/graph-keyboard-selection";
import { GraphScopeEvidence } from "@/components/graph-scope-evidence";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  useNodesInitialized,
  useViewport,
  useStore,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Focus, GitBranch, Loader2 } from "lucide-react";

import { GraphRelationshipDetail } from "@/components/graph-relationship-detail";
import { GraphEntityDrawer } from "@/components/graph-entity-drawer";
import { relationshipEdgeTypes } from "@/components/relationship-edge";
import { FullscreenButton, GraphInteractionToolbar, GraphLegend } from "@/components/graph-chrome";
import { useAuthState } from "@/components/auth-provider";
import { lineageNodeTypes, type LineageNodeData } from "@/components/lineage-nodes";
import { SigmaGraphOverview } from "@/components/sigma-graph-overview";
import { api } from "@/lib/api";
import type { GraphNodeNeighborsResponse } from "@/lib/api-types";
import type { AttackPath, UnifiedEdge, UnifiedGraphData, UnifiedNode } from "@/lib/graph-schema";
import {
  BACKGROUND_COLOR,
  BACKGROUND_GAP,
  CONTROLS_CLASS,
  graphNodeDisplayLabels,
  MINIMAP_BG,
  MINIMAP_CLASS,
  MINIMAP_MASK,
  legendItemsForVisibleGraph,
  minimapNodeColor,
  readableGraphEdges,
} from "@/lib/graph-utils";
import { readableGraphNodeStyle, readableLineageDagreLr } from "@/lib/graph-node-dimensions";
import { graphFitViewOptions, shouldShowGraphMiniMap } from "@/lib/graph-viewport";
import { decideGraphRenderer } from "@/lib/graph-renderer-switch";
import { mergeGraphNodeDetail } from "@/lib/graph-entity-detail";
import { buildFocusedGraphData, layersForFocusedPath, pathRelationshipIds } from "@/lib/security-graph-focus";
import { hopReceiptCoverage } from "@/lib/hop-receipt-coverage";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { useGraphLayout } from "@/lib/use-graph-layout";
import { useGraphPresentation } from "@/hooks/use-graph-presentation";
import { useWheelZoomGate, WheelZoomHint } from "@/hooks/use-wheel-zoom-gate";
import { CONTROLS_OVERLAY, fitPaddingAroundOverlay, viewportShowsNodes } from "@/lib/graph-viewport-fit";
import { graphTopologyKey, type GraphPresentationScope } from "@/lib/graph-presentation";
import { useCaptureMode } from "@/lib/use-capture-mode";
import { useElementWidth } from "@/hooks/use-element-width";
import { useRelationshipLabelControl } from "@/components/relationship-label-control";
import { InvestigationToolbar } from "@/components/investigation-toolbar";
import { PathToolbarLead } from "@/components/path-view-toolbar";
import { useNarrowViewport } from "@/hooks/use-narrow-viewport";
import { COLUMN_FIT_OPTIONS, applyColumnPath, columnCanvasHeight, columnFlowEdges, usesColumnPath } from "@/lib/path-card-column";
import { PATH_CARD_CANVAS_CLASS, pathCardCanvasHeight, pathCardEdges, pathCardNodeStyle } from "@/lib/path-card-canvas";
import { applySerpentinePath, planSerpentinePath } from "@/lib/path-serpentine-layout";
import { mergeGraphNeighborExpansions, boundedInvestigationGraph } from "@/lib/graph-neighbor-expansion";
import { withRiskContext } from "@/lib/exploit-story-canvas";

const INVESTIGATION_LAYERS = {
  provider: false,
  agent: true,
  org: false,
  account: false,
  user: false,
  group: false,
  role: false,
  policy: false,
  serviceAccount: false,
  servicePrincipal: false,
  federatedIdentity: false,
  environment: true,
  fleet: false,
  cluster: true,
  server: true,
  sharedServer: true,
  package: true,
  vulnerability: true,
  credential: true,
  tool: true,
  model: false,
  framework: true,
  dataset: false,
  container: true,
  cloudResource: true,
  misconfiguration: true,
  managedIdentity: false,
  accessGrant: false,
  accessPolicy: false,
  driftIncident: false,
  dataStore: false,
  directory: false,
  sourceFile: false,
  configFile: false,
  codeModule: false,
  ciJob: false,
  blueprint: false,
  // A gateway PROTECTS edge is what downgrades an exposure verdict, and a tool
  // call is the runtime evidence for a path hop — both belong in an
  // investigation even though the rest of the estate context is trimmed out.
  apiGateway: true,
  toolCall: true,
} as const;

/**
 * ReactFlow subtree with an imperative re-fit. ReactFlow's `fitView` prop only
 * runs once, at first mount — but the dagre layout positions nodes on a later
 * tick, and lens/focus/snapshot switches swap in an entirely new node set. When
 * the one-shot fit ran against the pre-layout (0,0) positions the canvas ended
 * up zoomed/panned off its content and rendered blank. Re-fitting whenever the
 * laid-out node set changes keeps the bounding box in view every time.
 */
function InvestigationFlow({
  nodes,
  edges,
  viewportInput,
  onNodeSelect,
  onEdgeSelect,
  selectedNodeId,
  presentationScope,
  persistenceEnabled,
  ownerActive,
  localMode,
  embedded = false,
  controls,
  pathNodeIds,
  roundedBottom = false,
  columnLayout = false,
}: {
  nodes: Node<LineageNodeData>[];
  edges: Edge[];
  viewportInput: {
    nodeCount: number;
    edgeCount: number;
    selectedNode: boolean;
    mode: "lineage" | "context";
  };
  onNodeSelect: (id: string) => void;
  onEdgeSelect: (edge: Edge) => void;
  selectedNodeId: string | null;
  presentationScope: GraphPresentationScope;
  persistenceEnabled: boolean;
  ownerActive: boolean;
  localMode: boolean;
  embedded?: boolean;
  controls?: React.ReactNode;
  pathNodeIds: string[];
  /** The embedded card lets toolbar popovers overflow, so the canvas rounds itself. */
  roundedBottom?: boolean;
  /** Narrow viewports stack a short path in one column instead of stepping node by node. */
  columnLayout?: boolean;
}) {
  const reactFlow = useReactFlow<Node<LineageNodeData>, Edge>();
  const { fitView } = reactFlow;
  const viewport = useViewport();
  const nodesInitialized = useNodesInitialized();
  const canvasWidth = useStore(state => state.width);
  const canvasHeight = useStore(state => state.height);
  const compact = useNarrowViewport(embedded);
  const stepper = compact && !columnLayout;
  const [navigationId, setNavigationId] = useState<string | null>(null);
  const [overview, setOverview] = useState(false);
  const manualViewportScope = useRef<string | null>(null);
  const wheelGate = useWheelZoomGate();
  const restoredViewportChecked = useRef<string | null>(null);
  const navigationNodes = useMemo(() => {
    const byId = new Map(nodes.map(node => [node.id, node]));
    const ordered = pathNodeIds.map(id => byId.get(id)).filter((node): node is Node<LineageNodeData> => Boolean(node));
    const pathIds = new Set(ordered.map(node => node.id));
    return [...ordered, ...nodes.filter(node => !pathIds.has(node.id))];
  }, [nodes, pathNodeIds]);
  const navigationIndex = Math.max(0, navigationNodes.findIndex(node => node.id === navigationId));
  const navigationNode = navigationNodes[navigationIndex];
  const responsiveScope = useMemo(() => compact
    ? { ...presentationScope, scope: `${presentationScope.scope}:${columnLayout ? "column-mobile" : "readable-mobile"}` }
    : presentationScope, [columnLayout, compact, presentationScope]);
  const controlsOverlay = CONTROLS_OVERLAY[embedded ? "horizontal" : "vertical"];
  const fitOptions = useMemo(() => {
    if (columnLayout) return COLUMN_FIT_OPTIONS;
    const options = graphFitViewOptions(viewportInput);
    // Text and badges grow as the viewport fits; reserve room for that final
    // measured size so the last finding is not clipped below the canvas, and
    // keep the bottom-left clear of the zoom controls so no label sits under them.
    const padding = embedded ? 0.12 : Math.max(0.2, options.padding);
    return { ...options, padding: fitPaddingAroundOverlay(padding, { width: canvasWidth, height: canvasHeight }, controlsOverlay) };
  }, [canvasHeight, canvasWidth, columnLayout, controlsOverlay, embedded, viewportInput]);
  const fitOptionsRef = useRef(fitOptions);
  fitOptionsRef.current = fitOptions;

  const presentation = useGraphPresentation({
    nodes,
    scope: responsiveScope,
    layout: "dagre-lr",
    enabled: persistenceEnabled,
    ownerActive,
    localMode,
  });
  const presentedEdges = useMemo(() => {
    const readable = readableGraphEdges(edges, undefined, {
      baseOpacity: 1,
      highSignalOpacity: 1,
      zoom: viewport.zoom,
      preserveLabelState: true,
      nodeLabels: graphNodeDisplayLabels(nodes),
    });
    return embedded ? pathCardEdges(readable, viewport.zoom) : readable;
  }, [edges, embedded, nodes, viewport.zoom]);
  const focusNode = useCallback((id: string) => {
    setNavigationId(id);
    setOverview(false);
    void fitView({ nodes: [{ id }], minZoom: 1, maxZoom: 1, padding: 0.08, duration: 200 });
  }, [fitView]);
  useEffect(() => {
    if (nodes.length === 0 || !nodesInitialized || !canvasWidth || !canvasHeight || manualViewportScope.current === presentation.storageKey) return;
    // A viewport restored from storage was fitted to an earlier canvas size
    // (or persisted by an automatic fit there). Judge it once per mount, not
    // on every re-measure or resize (node chrome scales with the zoom level,
    // so repeated fits do not converge on the same framing): keep it while it
    // shows the whole path on this canvas, else re-fit.
    if (presentation.restoredSavedState) {
      // The restored viewport is applied when the pane initialises; judging
      // the default (0, 0, 1) before then would accept any saved framing.
      if (!reactFlow.viewportInitialized || restoredViewportChecked.current === presentation.storageKey) return;
      if (viewportShowsNodes(reactFlow.getNodes(), reactFlow.getViewport(), { width: canvasWidth, height: canvasHeight }, controlsOverlay)) {
        restoredViewportChecked.current = presentation.storageKey;
        return;
      }
    }
    const raf = requestAnimationFrame(() => {
      // Marked only when the fit really runs: a dependency change can cancel
      // this frame, and the next pass must then still re-fit.
      restoredViewportChecked.current = presentation.storageKey;
      if (stepper && navigationNode) focusNode(navigationNode.id);
      else void fitView(fitOptionsRef.current);
    });
    return () => cancelAnimationFrame(raf);
  }, [canvasWidth, canvasHeight, controlsOverlay, stepper, fitView, focusNode, navigationNode, nodes, nodesInitialized, presentation.restoredSavedState, presentation.storageKey, reactFlow]);
  const fitVisible = useCallback(() => {
    manualViewportScope.current = null;
    setOverview(true);
    void fitView({ ...fitOptions, duration: 240 });
  }, [fitOptions, fitView]);
  const fitSelection = useCallback(() => {
    if (!selectedNodeId) return;
    const node = reactFlow.getNode(selectedNodeId);
    if (node) void fitView({ nodes: [node], padding: 0.7, duration: 240, maxZoom: 1.4 });
  }, [fitView, reactFlow, selectedNodeId]);
  const autoLayout = useCallback(() => {
    presentation.autoLayout();
    window.setTimeout(fitVisible, 0);
  }, [fitVisible, presentation]);
  const resetLayout = useCallback(() => {
    presentation.reset();
    window.setTimeout(fitVisible, 0);
  }, [fitVisible, presentation]);

  const layoutControls = <GraphInteractionToolbar
    editing={presentation.editing}
    hasSelection={Boolean(selectedNodeId)}
    onFitVisible={fitVisible}
    onFitSelection={fitSelection}
    onAutoLayout={autoLayout}
    onReset={resetLayout}
    onToggleEditing={presentation.toggleEditing}
  />;

  return (
    <div className="flex h-full min-h-0 flex-col">
      {(embedded || presentation.enabled) && nodes.length > 0 && <InvestigationToolbar
        embedded={embedded}
        compact={compact}
        stepper={stepper ? {
          overview,
          nodeCount: nodes.length,
          index: navigationIndex,
          count: navigationNodes.length,
          onPrevious: () => focusNode(navigationNodes[navigationIndex - 1]!.id),
          onNext: () => focusNode(navigationNodes[navigationIndex + 1]!.id),
          onReadable: () => { if (navigationNode) focusNode(navigationNode.id); },
        } : null}
        controls={controls}
        layoutControls={presentation.enabled ? layoutControls : null}
      />}
      <div className={`relative min-h-0 flex-1 ${roundedBottom ? "overflow-hidden rounded-b-2xl" : ""}`} {...wheelGate.handlers}>
        <WheelZoomHint visible={wheelGate.hintVisible} />
        <ReactFlow
          style={embedded ? pathCardNodeStyle(viewport.zoom) : readableGraphNodeStyle(viewport.zoom)}
          key={`${presentation.storageKey}:${presentation.restoredSavedState ? "restored" : "fresh"}`}
          nodes={presentation.nodes}
          edges={presentedEdges}
          nodeTypes={lineageNodeTypes}
          edgeTypes={relationshipEdgeTypes}
          fitView={!stepper && !presentation.hasSavedState && !presentation.restoredSavedState}
          fitViewOptions={fitOptions}
          minZoom={0.2}
          maxZoom={2.5}
          defaultViewport={presentation.restoredViewport ?? presentation.viewport}
          // Map convention: a plain wheel scrolls the page; Ctrl/⌘ + wheel or a
          // click on the canvas arms zooming (see useWheelZoomGate).
          zoomOnScroll={wheelGate.armed}
          zoomOnPinch
          // A whole stacked path needs no panning; touch drags scroll the page.
          panOnDrag={!columnLayout}
          preventScrolling={!columnLayout && wheelGate.armed}
          nodesDraggable={presentation.editing}
          nodesConnectable={false}
          nodesFocusable
          edgesFocusable
          elementsSelectable
          deleteKeyCode={null}
          onNodesChange={presentation.onNodesChange}
          onNodeDragStop={presentation.onNodeDragStop}
          onMoveStart={event => {
            // An automatic fit also emits move events. Only operator gestures
            // pin this mount; a newly persisted automatic camera can still fit
            // when opening the queue or resizing the canvas.
            if (event) manualViewportScope.current = presentation.storageKey;
          }}
          onMoveEnd={presentation.onMoveEnd}
          onNodeClick={(_, node) => { setNavigationId(node.id); onNodeSelect(node.id); }}
          onEdgeClick={(_, edge) => onEdgeSelect(edge)}
          onKeyDownCapture={event => {
                if (activateGraphNodeFromKeyboard(event)) return;
            if (event.key !== "Enter" && event.key !== " ") return;
            const id = event.target instanceof Element ? event.target.closest(".react-flow__edge")?.getAttribute("data-id") : null;
            const edge = id ? presentedEdges.find(item => item.id === id) : undefined;
            if (edge) { event.preventDefault(); event.stopPropagation(); onEdgeSelect(edge); }
          }}
          proOptions={{ hideAttribution: true }}
        >
          <Background color={BACKGROUND_COLOR} gap={BACKGROUND_GAP} />
          <Controls className={CONTROLS_CLASS} showInteractive={false} onFitView={fitVisible} orientation={embedded ? "horizontal" : "vertical"} />
          {!compact && shouldShowGraphMiniMap(viewportInput) && (
            <MiniMap
              className={MINIMAP_CLASS}
              style={{ background: MINIMAP_BG }}
              maskColor={MINIMAP_MASK}
              nodeColor={minimapNodeColor}
            />
          )}
        </ReactFlow>
      </div>
    </div>
  );
}

const SERPENTINE_MIN_HOP_NODES = 6;

export function SecurityGraphInvestigation({
  graph,
  attackPath,
  focusMode,
  onFocusModeChange,
  fullGraphHref,
  loading = false,
  scanId,
  onPinnedNodeChange,
  onStepHint,
  embedded = false,
  riskContext = null,
}: {
  graph: UnifiedGraphData | null;
  attackPath: AttackPath | null;
  focusMode: boolean;
  onFocusModeChange: (next: boolean) => void;
  fullGraphHref: string;
  loading?: boolean;
  scanId?: string | undefined;
  onPinnedNodeChange?: ((nodeId: string | null) => void) | undefined;
  /** Notify parent when expand/impact actions advance the investigation step. */
  onStepHint?: ((step: "expand" | "impact" | "fix") => void) | undefined;
  /** The parent already supplies the selected path title and receipt assessment. */
  embedded?: boolean;
  /** Recorded at-risk hops past the path (exploit story) to draw beside it. */
  riskContext?: { nodes: UnifiedNode[]; edges: UnifiedEdge[] } | null | undefined;
}) {
  const captureMode = useCaptureMode();
  const { session, loading: authLoading } = useAuthState();
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<Edge | null>(null);
  const [drawerData, setDrawerData] = useState<LineageNodeData | null>(null);
  const [blastLoading, setBlastLoading] = useState(false);
  const [blastActive, setBlastActive] = useState(false);
  const [neighborExpansions, setNeighborExpansions] = useState<
    Record<string, GraphNodeNeighborsResponse>
  >({});
  const [contextPage, setContextPage] = useState(0);
  const lastPinnedRef = useRef<string | null>(null);
  const investigationRequest = useRef(0);
  useEffect(() => {
    investigationRequest.current += 1;
    setBlastLoading(false);
    setBlastActive(false);
    return () => {
      investigationRequest.current += 1;
    };
  }, [selectedNodeId, scanId, graph?.scan_id, graph?.snapshot_generation, session?.tenant_id, focusMode, attackPath]);

  const activeGraph = useMemo(() => {
    if (!graph) return null;
    const base = focusMode && attackPath
      ? buildFocusedGraphData(graph, attackPath)
      : graph;
    if (!base) return null;
    return mergeGraphNeighborExpansions(withRiskContext(base, riskContext), Object.values(neighborExpansions));
  }, [attackPath, focusMode, graph, neighborExpansions, riskContext]);

  useEffect(() => {
    setNeighborExpansions({});
    setContextPage(0);
  }, [attackPath, focusMode, graph?.scan_id, graph?.snapshot_generation, scanId, session?.tenant_id]);

  const bounded = useMemo(() => activeGraph ? boundedInvestigationGraph(
    activeGraph, attackPath?.hops ?? [], contextPage,
  ) : null, [activeGraph, attackPath, contextPage]);

  const flow = useMemo(() => {
    if (!activeGraph) {
      return { nodes: [] as Node<LineageNodeData>[], edges: [] as Edge[], legend: [] };
    }
    return buildUnifiedFlowGraph(bounded!.graph, {
      layers: layersForFocusedPath(activeGraph, focusMode ? attackPath : null, INVESTIGATION_LAYERS),
      severity: null,
      agentName: null,
      vulnOnly: false,
      maxDepth: 12,
    });
  }, [activeGraph, attackPath, bounded, focusMode]);

  const layout = useGraphLayout(focusMode ? "dagre-lr" : "asset-hierarchy", flow.nodes, flow.edges, {
    dagreLr: readableLineageDagreLr({ rankSep: 96, nodeSep: 40 }),
  });
  const canvasRef = useRef<HTMLDivElement>(null);
  const canvasWidth = useElementWidth(canvasRef);
  // Long focused paths wrap into alternating rows sized to the canvas, so
  // labels stay readable instead of shrinking a single row to fit.
  const pathLayout = useMemo(() => {
    const hops = attackPath?.hops ?? [];
    if (!focusMode || hops.length < SERPENTINE_MIN_HOP_NODES || canvasWidth <= 0) return null;
    const plan = planSerpentinePath(layout.nodes.length, {
      containerWidth: canvasWidth,
      maxCanvasHeight: embedded ? 600 : 680,
    });
    // Narrow canvases keep the step-through focused view on the default layout.
    if (plan.columns < 2) return null;
    const nodes = applySerpentinePath(layout.nodes, hops, plan.columns);
    return nodes === layout.nodes ? null : { plan, nodes };
  }, [attackPath, canvasWidth, embedded, focusMode, layout.nodes]);
  // A phone shows a short path whole, one hop per row, instead of stepping through it.
  const narrow = useNarrowViewport(embedded);
  const columnNodes = useMemo(() => usesColumnPath({ narrow, focusMode, nodeCount: layout.nodes.length })
    ? applyColumnPath(layout.nodes, attackPath?.hops ?? []) : layout.nodes, [attackPath, focusMode, layout.nodes, narrow]);
  const columnLayout = columnNodes !== layout.nodes;
  const canvasNodes = columnLayout ? columnNodes : pathLayout?.nodes ?? layout.nodes;
  // A short focused path gets a short canvas; the bounded clamp stays for context views.
  const canvasHeight = columnLayout ? columnCanvasHeight(columnNodes.length) : pathLayout?.plan.canvasHeight
    ?? (embedded && focusMode && !loading && layout.nodes.length > 0 ? pathCardCanvasHeight(layout.nodes) : undefined);
  const pathEdges = useMemo(() => focusMode && attackPath ? pathRelationshipIds(layout.edges, attackPath) : new Set<string>(), [focusMode, attackPath, layout.edges]);
  const displayEdges = useMemo(() => {
    const readable = readableGraphEdges(layout.edges.map(edge => ({ ...edge, data: { ...edge.data,
      pathEmphasis: pathEdges.has(edge.id),
      directionEmphasis: pathEdges.has(edge.id) || edge.id === selectedEdge?.id || edge.source === selectedNodeId || edge.target === selectedNodeId,
      quietLabel: edge.data?.quietLabel && edge.id !== selectedEdge?.id && edge.source !== selectedNodeId && edge.target !== selectedNodeId,
    } })), undefined, { nodeLabels: graphNodeDisplayLabels(layout.nodes) });
    return columnLayout ? columnFlowEdges(readable, attackPath?.hops ?? []) : readable;
  }, [attackPath, columnLayout, layout.edges, layout.nodes, selectedEdge?.id, selectedNodeId, pathEdges]);
  const relationshipLabels = useRelationshipLabelControl(displayEdges);
  const legendItems = useMemo(
    () => legendItemsForVisibleGraph(layout.nodes, displayEdges),
    [displayEdges, layout.nodes],
  );
  const viewportInput = useMemo(
    () => ({
      nodeCount: layout.nodes.length,
      edgeCount: displayEdges.length,
      selectedNode: Boolean(selectedNodeId),
      // Focused attack paths are short chains — use context framing so fitView
      // fills the investigation canvas instead of parking a tiny path mid-pane.
      mode: (focusMode ? "context" : "lineage") as "context" | "lineage",
    }),
    [displayEdges.length, focusMode, layout.nodes.length, selectedNodeId],
  );
  const rendererDecision = useMemo(
    () =>
      decideGraphRenderer({
        nodeCount: layout.nodes.length,
        edgeCount: displayEdges.length,
        captureMode,
        selectedAttackPath: focusMode,
      }),
    [captureMode, displayEdges.length, focusMode, layout.nodes.length],
  );
  const evidenceBadges = useMemo(() => {
    if (!attackPath) return [] as Array<{ label: string; tone: string }>;
    const receipts = attackPath.hop_evidence ?? [];
    const badges: Array<{ label: string; tone: string }> = [];
    if (receipts.some((receipt) => receipt.evidence_tier === "static_scan")) {
      badges.push({ label: "Read from files or configuration", tone: "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300" });
    }
    if (receipts.some((receipt) => receipt.evidence_tier === "modeled_infrastructure")) {
      badges.push({ label: "Modeled infrastructure", tone: "border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300" });
    }
    if (receipts.some((receipt) => receipt.runtime_observed_state === "observed")) {
      badges.push({ label: "Runtime observed", tone: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300" });
    }
    if (receipts.some((receipt) => receipt.runtime_observed_state === "blocked")) {
      badges.push({ label: "Runtime blocked", tone: "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300" });
    }
    if (receipts.some((receipt) => receipt.freshness === "stale_allowed")) {
      badges.push({ label: "Stale allowed", tone: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300" });
    }
    if (attackPath.analysis?.status && attackPath.analysis.status !== "complete") {
      badges.push({ label: "Bounded analysis", tone: "border-orange-500/30 bg-orange-500/10 text-orange-700 dark:text-orange-300" });
    }
    return badges;
  }, [attackPath]);
  const presentationScope = useMemo(
    () => ({
      tenantId: session?.tenant_id || "local",
      subject: session?.subject || session?.auth_method || "local-viewer",
      snapshotId: scanId || "unselected",
      lens: "investigation",
      scope: JSON.stringify({
        focus: focusMode && attackPath ? attackPath.hops.join("=>") : "full-snapshot",
        layout: focusMode ? "dagre-lr" : "evidence-flow-v1",
        topology: graphTopologyKey(layout.nodes, displayEdges),
      }),
    }),
    [attackPath, displayEdges, focusMode, layout.nodes, scanId, session?.auth_method, session?.subject, session?.tenant_id],
  );

  const selectedRelationship = useMemo(() => {
    if (!selectedEdge || !displayEdges.some(edge => edge.id === selectedEdge.id)) return null;
    // Bind to the exact displayed edge, including endpoints. A parallel edge
    // between the same nodes must never donate a different relationship receipt.
    return activeGraph?.edges.find(edge => edge.id === selectedEdge.id
      && edge.source === selectedEdge.source && edge.target === selectedEdge.target
      && edge.relationship === selectedEdge.data?.relationship) ?? null;
  }, [activeGraph, displayEdges, selectedEdge]);

  const canvasLast = !selectedRelationship && !drawerData;

  const selectedNode = useMemo(
    () => layout.nodes.find((node) => node.id === selectedNodeId) ?? null,
    [layout.nodes, selectedNodeId],
  );

  useEffect(() => {
    if (!selectedNodeId) {
      setDrawerData(null);
      lastPinnedRef.current = null;
      onPinnedNodeChange?.(null);
      return;
    }
    if (!layout.nodes.some((node) => node.id === selectedNodeId)) {
      setSelectedNodeId(null);
      return;
    }
    if (!selectedNode) return;
    const base = {
      ...(selectedNode.data as LineageNodeData),
      attributes: {
        ...((selectedNode.data as LineageNodeData).attributes ?? {}),
        node_id: selectedNode.id,
      },
    };
    setDrawerData(base);
    const isNewPin = lastPinnedRef.current !== selectedNode.id;
    lastPinnedRef.current = selectedNode.id;
    if (isNewPin) {
      onPinnedNodeChange?.(selectedNode.id);
      // Pinning a node advances the operator into Expand — parent owns step URL.
      onStepHint?.("expand");
    }
    // Intentionally omit callback identities from deps to avoid re-notify loops.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layout.nodes, selectedNode, selectedNodeId]);

  async function handleExpandNeighbors() {
    if (!selectedNodeId || !scanId) return;
    const request = ++investigationRequest.current;
    setBlastLoading(false);
    setBlastActive(false);
    onStepHint?.("expand");
    try {
      const neighbors = await api.getGraphNodeNeighbors(selectedNodeId, {
        scanId,
        limit: 24,
        direction: "both",
      });
      if (request !== investigationRequest.current) return;
      setNeighborExpansions((current) => ({ ...current, [selectedNodeId]: neighbors }));
      setDrawerData((current) =>
        current?.attributes?.node_id === selectedNodeId
          ? {
              ...current,
              neighborCount: neighbors.total_neighbors ?? undefined,
              relationshipCountsPartial: neighbors.total_neighbors === null || neighbors.truncated,
              attributes: {
                ...(current.attributes ?? {}),
                node_id: selectedNodeId,
                expanded_neighbor_ids: neighbors.neighbors.map((node) => node.id),
                expanded_neighbor_returned: neighbors.neighbors.length,
                expanded_neighbor_omitted: neighbors.total_neighbors === null ? null : Math.max(
                  0,
                  neighbors.total_neighbors - neighbors.neighbors.length,
                ),
                expanded_neighbor_truncated: neighbors.truncated,
              },
            }
          : current,
      );
    } catch {
      /* keep prior drawer state */
    }
  }

  async function handleShowImpact() {
    if (!selectedNodeId || !scanId) return;
    const request = ++investigationRequest.current;
    onStepHint?.("impact");
    setBlastLoading(true);
    try {
      const [detail, impact] = await Promise.all([
        api.getGraphNode(selectedNodeId, scanId),
        api.getGraphImpact(selectedNodeId, scanId),
      ]);
      if (request !== investigationRequest.current) return;
      setDrawerData((current) => {
        if (!current || current.attributes?.node_id !== selectedNodeId) return current;
        const merged = mergeGraphNodeDetail(current, detail);
        return {
          ...merged,
          impactCount: impact.affected_count,
          maxImpactDepth: impact.max_depth_reached,
          impactByType: impact.affected_by_type,
          impactCompleteness: impact.completeness,
        };
      });
      setBlastActive(true);
    } catch {
      if (request === investigationRequest.current) setBlastActive(false);
    } finally {
      if (request === investigationRequest.current) setBlastLoading(false);
    }
  }

  const graphControls = <>
          {rendererDecision.kind === "react-flow" && relationshipLabels.control}

          <button
            type="button"
            onClick={() => onFocusModeChange(!focusMode)}
            className={`inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
              focusMode
                ? "border-emerald-600/50 bg-emerald-500/10 text-emerald-700 dark:text-emerald-200"
                : "border-outline bg-surface-muted text-ink-secondary"
            }`}
          >
            <Focus className="h-3.5 w-3.5" />
            {focusMode ? "Focus on path" : "Loaded context"}
          </button>
          <Link
            href={fullGraphHref}
            className="inline-flex items-center gap-2 rounded-lg border border-outline bg-surface-muted px-3 py-1.5 text-xs font-medium text-foreground transition hover:border-outline-strong"
          >
            Open lineage
            <GitBranch className="h-3.5 w-3.5" />
          </Link>
          <FullscreenButton />

    {embedded && rendererDecision.kind === "react-flow" && layout.nodes.length > 0 ? (
      <div data-testid="security-graph-legend-band"><GraphLegend items={legendItems} footer={<GraphScopeEvidence edges={relationshipLabels.edges} inline />} /></div>
    ) : null}
  </>;

  return (
    <section className={`rounded-2xl border border-outline bg-surface ${embedded ? "" : "overflow-hidden"}`}>
      {!embedded && <GraphScopeEvidence edges={relationshipLabels.edges} />}
      {!embedded && (<div className="flex flex-wrap items-center justify-between gap-3 border-b border-outline px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold text-foreground">Interactive graph</h2>
          <p className="mt-0.5 text-xs text-ink-secondary">
            {focusMode
              ? "Focus mode highlights the selected exposure path. Pin a node to expand neighbors and impact."
              : "Loaded context shows a bounded page of recorded relationships. Expand neighbors to request more evidence."}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">{graphControls}</div>
      </div>)}

      {!embedded && attackPath && evidenceBadges.length > 0 ? (
        <div
          className="flex flex-wrap items-center gap-2 border-b border-outline bg-surface-elevated px-3 py-2"
          data-testid="attack-path-evidence-badges"
        >
          <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-ink-tertiary">Path proof</span>
          {evidenceBadges.map((badge) => (
            <span key={badge.label} className={`rounded-full border px-2 py-1 text-[10px] font-medium ${badge.tone}`}>
              {badge.label}
            </span>
          ))}
          <span className="text-[10px] text-ink-tertiary">
            {hopReceiptCoverage(attackPath).summary}
          </span>
        </div>
      ) : null}

      {!embedded && rendererDecision.kind === "react-flow" && layout.nodes.length > 0 ? (
        <div
          className="border-b border-outline bg-surface px-3 py-2"
          data-testid="security-graph-legend-band"
        >
          <GraphLegend items={legendItems} />
        </div>
      ) : null}

      {embedded && rendererDecision.kind === "webgl" && <div role="toolbar" aria-label="Graph controls" className="flex flex-wrap items-center justify-end gap-2 border-b border-outline px-3 py-2">
        <PathToolbarLead />
        <GraphScopeEvidence edges={relationshipLabels.edges} inline />
        {graphControls}
      </div>}

      {bounded && bounded.omittedNodes > 0 && <div className="flex flex-wrap items-center justify-between gap-2 border-b border-outline px-3 py-2 text-xs" aria-label="Loaded graph context pages">
        <p role="status">{layout.nodes.length} nodes on canvas · {bounded.omittedNodes} loaded context nodes bundled off canvas. Path nodes take priority within the canvas limit. Counts describe loaded evidence.</p>
        <div className="flex gap-2">
          <button type="button" disabled={bounded.page === 0} className="graph-page-action disabled:opacity-50" onClick={() => setContextPage(bounded.page - 1)}>Previous context</button>
          <button type="button" disabled={bounded.page + 1 >= bounded.pageCount} className="graph-page-action disabled:opacity-50" onClick={() => setContextPage(bounded.page + 1)}>Expand next context bundle</button>
        </div>
      </div>}
      <div
        ref={canvasRef}
        id="security-graph-investigation-canvas"
        className={`relative bg-surface-muted ${embedded ? `h-[clamp(24rem,42vh,34rem)] ${PATH_CARD_CANVAS_CLASS} ${canvasLast ? "rounded-b-2xl" : ""}` : "h-[clamp(32rem,56vh,42rem)]"}`}
        style={canvasHeight ? { height: canvasHeight } : undefined}
        data-testid="security-graph-investigation"
        data-path-layout={pathLayout ? `serpentine-${pathLayout.plan.columns}x${pathLayout.plan.rows}` : undefined}
      >
        {loading ? (
          <div className="flex h-full items-center justify-center gap-2 text-sm text-ink-secondary">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading graph evidence…
          </div>
        ) : layout.nodes.length === 0 ? (
          <div className="flex h-full items-center justify-center px-6 text-center text-sm text-ink-secondary">
            Selected path nodes are not available in this graph page. Use Path or List to inspect the supplied path evidence, or open lineage for broader context.
          </div>
        ) : rendererDecision.kind === "webgl" ? (
          <SigmaGraphOverview
            nodes={layout.nodes as Node<LineageNodeData>[]}
            edges={relationshipLabels.edges}
            legendItems={legendItems}
            embedded
            onNodeSelect={setSelectedNodeId}
            presentationScope={presentationScope}
            presentationEnabled={!authLoading && Boolean(session)}
          />
        ) : (
          <ReactFlowProvider>
            <InvestigationFlow
              nodes={canvasNodes as Node<LineageNodeData>[]}
              edges={relationshipLabels.edges}
              viewportInput={viewportInput}
              onNodeSelect={id => { setSelectedEdge(null); setSelectedNodeId(id); }}
              onEdgeSelect={edge => { setSelectedNodeId(null); setSelectedEdge(edge); }}
              selectedNodeId={selectedNodeId}
              presentationScope={presentationScope}
              persistenceEnabled={!authLoading && Boolean(session)}
              ownerActive={Boolean(session)}
              localMode={session?.recommended_ui_mode === "no_auth"}
              embedded={embedded}
              pathNodeIds={attackPath?.hops ?? []}
              controls={embedded ? graphControls : undefined}
              columnLayout={columnLayout}
              roundedBottom={embedded && canvasLast}
            />
          </ReactFlowProvider>
        )}
      </div>

      {selectedRelationship && <GraphRelationshipDetail edge={selectedRelationship} scanId={scanId ?? ""}
        sourceType={activeGraph?.nodes.find(node => node.id === selectedRelationship.source)?.entity_type}
        targetType={activeGraph?.nodes.find(node => node.id === selectedRelationship.target)?.entity_type}
        sourceLabel={activeGraph?.nodes.find(node => node.id === selectedRelationship.source)?.label ?? selectedRelationship.source}
        targetLabel={activeGraph?.nodes.find(node => node.id === selectedRelationship.target)?.label ?? selectedRelationship.target}
        onClose={() => setSelectedEdge(null)} mobile />}

      {drawerData && (
        <div className="border-t border-outline p-4">
          <GraphEntityDrawer
            data={drawerData}
            scanId={scanId}
            variant="inline"
            onClose={() => {
              setSelectedNodeId(null);
              setDrawerData(null);
              setBlastActive(false);
              onPinnedNodeChange?.(null);
            }}
            blastRadiusActive={blastActive}
            blastRadiusLoading={blastLoading}
            onShowBlastRadius={scanId ? () => void handleShowImpact() : undefined}
            onExpandNeighbors={scanId ? () => void handleExpandNeighbors() : undefined}
            onShowImpact={scanId ? () => void handleShowImpact() : undefined}
            remediationHref="/remediation"
          />
        </div>
      )}
    </section>
  );
}
