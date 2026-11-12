"use client";

import { Background, ControlButton, Controls, Panel, ReactFlow, ReactFlowProvider, useReactFlow, useStore, Position } from "@xyflow/react";
import { Maximize } from "lucide-react";
import "@xyflow/react/dist/style.css";
import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";

import { AttackPathArrowDefs, attackPathEdgeTypes, type AttackPathFlowEdge } from "@/components/attack-path-graph-edge";
import { AttackPathGraphLegend } from "@/components/attack-path-graph-legend";
import { attackPathNodeTypes, type AttackPathFlowNode } from "@/components/attack-path-graph-node";
import { useElementWidth } from "@/hooks/use-element-width";
import { activateGraphNodeFromKeyboard } from "@/lib/graph-keyboard-selection";
import { useWheelZoomGate, WheelZoomHint } from "@/hooks/use-wheel-zoom-gate";
import { DESKTOP_MIN_ZOOM, NARROW_MIN_ZOOM, attackPathCanvasHeight, layoutAttackPathGraph, type AttackPathLayout } from "@/lib/attack-path-graph-layout";
import { GLYPH_CENTER_Y, glyphInsetX, routeAttackPathEdges } from "@/lib/attack-path-graph-routes";
import { attackPathViewport } from "@/lib/attack-path-graph-viewport";
import { buildAttackPathGraphModel, type AttackPathGraphModel } from "@/lib/attack-path-graph-model";
import type { AttackPath, UnifiedEdge, UnifiedGraphData, UnifiedNode } from "@/lib/graph-schema";
import { BACKGROUND_GAP, CONTROLS_CLASS } from "@/lib/graph-utils";

export type AttackPathGraphProps = {
  graph: UnifiedGraphData;
  attackPath: AttackPath;
  /** Phones stack the path top to bottom. */
  narrow: boolean;
  onNodeSelect: (nodeId: string) => void;
  onEdgeSelect: (edge: { id: string; source: string; target: string; relationship: string }) => void;
  onOpenFindings: (nodeId: string, findingIds: string[]) => void;
  /** Recorded at-risk hops past the path (exploit story), drawn where a recorded edge reaches them. */
  context?: { nodes: UnifiedNode[]; edges: UnifiedEdge[] } | null | undefined;
  /** Toolbar row rendered above the canvas (focus toggle, lineage, fullscreen). */
  toolbar?: React.ReactNode;
};

/** Only a node's glyph, label and buttons take pointer input; its empty box never swallows a click meant for a line. */
const HIT_AREAS = "[&_[aria-roledescription=node]]:pointer-events-none! [&_[data-node-glyph]]:pointer-events-auto! [&_[data-node-label]]:pointer-events-auto! [&_[aria-roledescription=node]_button]:pointer-events-auto!";
/** "Fit all" may go below the readable floor because the operator asked for the overview. */
const OVERVIEW_MIN_ZOOM = 0.25;

/**
 * The camera, computed from the layout rather than React Flow's `fitView()`
 * (which version 12 queues until the next node update, so a resize alone kept
 * a stale camera). Auto-framing never overrides a camera the operator moved.
 */
function Camera({ layout, spineIds, nodesKey, floor, manual }: {
  layout: AttackPathLayout; spineIds: readonly string[]; nodesKey: string; floor: number; manual: React.RefObject<string | null>;
}) {
  const { setViewport } = useReactFlow();
  const width = useStore(state => state.width);
  const height = useStore(state => state.height);
  const [overviewFor, setOverviewFor] = useState<string | null>(null);
  const framed = useMemo(() => width && height ? attackPathViewport(layout, spineIds, { width, height }, floor) : null, [floor, height, layout, spineIds, width]);
  const frame = useCallback((overview: boolean) => {
    if (!width || !height) return;
    const view = overview ? attackPathViewport(layout, spineIds, { width, height }, floor, { minZoom: OVERVIEW_MIN_ZOOM }) : framed!;
    void setViewport({ x: view.x, y: view.y, zoom: view.zoom });
  }, [floor, framed, height, layout, setViewport, spineIds, width]);
  useEffect(() => {
    if (manual.current !== nodesKey) frame(false);
  }, [frame, manual, nodesKey]);
  const fitAll = () => { manual.current = null; setOverviewFor(nodesKey); frame(true); };
  const offscreen = framed?.fallback && overviewFor !== nodesKey ? framed.hiddenNodeIds.length : 0;
  return <>
    <Controls className={CONTROLS_CLASS} showInteractive={false} showFitView={false} orientation="horizontal" position="bottom-left">
      <ControlButton className="react-flow__controls-fitview" title="fit view" aria-label="fit view" onClick={fitAll}>
        <Maximize aria-hidden="true" />
      </ControlButton>
    </Controls>
    {offscreen > 0 && <Panel position="bottom-right">
      <p role="status" className="flex items-center gap-2 rounded-lg border border-outline bg-surface px-2.5 py-1 text-xs text-ink-secondary shadow-sm">
        {offscreen} more {offscreen === 1 ? "node" : "nodes"} off screen · drag to pan or
        <button type="button" onClick={fitAll} className="font-semibold text-[color:var(--accent)] underline-offset-2 hover:underline">Fit all</button>
      </p>
    </Panel>}
  </>;
}

function edgeFromTarget(target: EventTarget | null): string | null {
  return target instanceof Element ? target.closest(".react-flow__edge")?.getAttribute("data-id") ?? null : null;
}

function useFlowElements(model: AttackPathGraphModel, narrow: boolean, activeEdge: string | null, markerPrefix: string,
  handlers: { onOpenFindings: AttackPathGraphProps["onOpenFindings"]; onExpandGroup: (id: string) => void }) {
  const layout = useMemo(() => layoutAttackPathGraph(model, narrow ? "TB" : "LR"), [model, narrow]);
  const routes = useMemo(() => routeAttackPathEdges(model, layout), [layout, model]);
  const inset = glyphInsetX(layout.nodeWidth);
  const nodes = useMemo<AttackPathFlowNode[]>(() => model.nodes.map(node => {
    const handles = narrow
      ? [{ type: "target" as const, position: Position.Top, x: layout.nodeWidth / 2, y: 0, width: 1, height: 1, id: null },
        { type: "source" as const, position: Position.Bottom, x: layout.nodeWidth / 2, y: layout.nodeHeight, width: 1, height: 1, id: null }]
      : [{ type: "target" as const, position: Position.Left, x: inset, y: GLYPH_CENTER_Y, width: 1, height: 1, id: null },
        { type: "source" as const, position: Position.Right, x: layout.nodeWidth - inset, y: GLYPH_CENTER_Y, width: 1, height: 1, id: null }];
    return {
      id: node.id, type: "attackPathNode", position: layout.positions.get(node.id)!,
      width: layout.nodeWidth, height: layout.nodeHeight, handles,
      ariaLabel: `${node.label}, ${node.typeLabel}${node.findings.length ? `, ${node.findings.length} findings` : ""}`,
      data: { node, vertical: narrow, ...handlers },
    };
  }), [handlers, inset, layout, model.nodes, narrow]);
  const labels = useMemo(() => new Map(model.nodes.map(node => [node.id, node.label])), [model.nodes]);
  const edges = useMemo<AttackPathFlowEdge[]>(() => model.edges.map(edge => ({
    id: edge.id, source: edge.source, target: edge.target, type: "attackPathEdge",
    ariaLabel: `${labels.get(edge.source)} ${edge.relationshipLabel.toLowerCase()} ${labels.get(edge.target)}`,
    data: { edge, active: edge.id === activeEdge, markerPrefix, direction: layout.direction, route: routes.get(edge.id)! },
  })), [activeEdge, labels, layout.direction, markerPrefix, model.edges, routes]);
  return { layout, nodes, edges };
}

function AttackPathCanvas({ graph, attackPath, narrow, context, onNodeSelect, onEdgeSelect, onOpenFindings }: AttackPathGraphProps) {
  const [expandedGroups, setExpandedGroups] = useState<ReadonlySet<string>>(new Set());
  const [activeEdge, setActiveEdge] = useState<string | null>(null);
  const markerPrefix = `apg${useId().replaceAll(":", "")}`;
  const wheelGate = useWheelZoomGate();
  const model = useMemo(() => buildAttackPathGraphModel(graph, attackPath, { expandedGroups, context }), [attackPath, context, expandedGroups, graph]);
  const onExpandGroup = useCallback((id: string) => setExpandedGroups(current => new Set([...current, id])), []);
  const handlers = useMemo(() => ({ onOpenFindings, onExpandGroup }), [onExpandGroup, onOpenFindings]);
  const { layout, nodes, edges } = useFlowElements(model, narrow, activeEdge, markerPrefix, handlers);
  const frameRef = useRef<HTMLDivElement>(null);
  const frameWidth = useElementWidth(frameRef);
  const height = attackPathCanvasHeight(layout, narrow, frameWidth);
  const nodesKey = nodes.map(node => node.id).join("|");
  const manualCamera = useRef<string | null>(null);
  // Collapsed-group links stand in for several records; only a recorded edge has a receipt.
  const openEdge = (edge: AttackPathFlowEdge) => {
    if (graph.edges.some(item => item.id === edge.id) || context?.edges.some(item => item.id === edge.id)) onEdgeSelect({ id: edge.id, source: edge.source, target: edge.target, relationship: edge.data!.edge.relationship });
  };
  return <>
    <div ref={frameRef} className={`relative bg-surface ${HIT_AREAS}`} style={{ height }} data-testid="attack-path-graph-canvas" data-graph-annotations="on-demand"
      onFocusCapture={event => { const id = edgeFromTarget(event.target); if (id) setActiveEdge(id); }}
      onBlurCapture={event => { if (edgeFromTarget(event.target)) setActiveEdge(null); }}
      onKeyDownCapture={event => {
        if (activateGraphNodeFromKeyboard(event) || (event.key !== "Enter" && event.key !== " ")) return;
        const edge = edges.find(item => item.id === edgeFromTarget(event.target));
        if (!edge) return;
        event.preventDefault();
        openEdge(edge);
      }}
      {...wheelGate.handlers}>
      <AttackPathArrowDefs prefix={markerPrefix} />
      <WheelZoomHint visible={wheelGate.hintVisible} />
      <ReactFlow<AttackPathFlowNode, AttackPathFlowEdge>
        nodes={nodes} edges={edges} nodeTypes={attackPathNodeTypes} edgeTypes={attackPathEdgeTypes}
        minZoom={OVERVIEW_MIN_ZOOM} maxZoom={2}
        zoomOnScroll={wheelGate.armed} preventScrolling={wheelGate.armed} zoomOnPinch panOnDrag={!narrow}
        nodesDraggable={false} nodesConnectable={false} nodesFocusable edgesFocusable elementsSelectable deleteKeyCode={null}
        onNodeClick={(_, node) => onNodeSelect(node.id)}
        onEdgeClick={(_, edge) => openEdge(edge)}
        onEdgeMouseEnter={(_, edge) => setActiveEdge(edge.id)}
        onEdgeMouseLeave={() => setActiveEdge(null)}
        // Automatic fits emit move events without a source event; only gestures pin the camera.
        onMoveStart={event => { if (event) manualCamera.current = nodesKey; }}
        proOptions={{ hideAttribution: true }}>
        <Background gap={BACKGROUND_GAP} color="var(--border-subtle)" />
        <Camera layout={layout} spineIds={model.pathNodeIds} nodesKey={nodesKey} floor={narrow ? NARROW_MIN_ZOOM : DESKTOP_MIN_ZOOM} manual={manualCamera} />
      </ReactFlow>
    </div>
    {model.connectedPathCount > 0 && <p className="border-t border-outline bg-surface px-3 pt-2 text-xs text-ink-secondary">
      Branches show {model.connectedPathCount - model.omittedConnectedPaths} other recorded {model.connectedPathCount - model.omittedConnectedPaths === 1 ? "path that shares" : "paths that share"} a node or relationship with this path
      {model.omittedConnectedPaths > 0 ? `; ${model.omittedConnectedPaths} lower-risk connected ${model.omittedConnectedPaths === 1 ? "path is" : "paths are"} not drawn` : ""}.
    </p>}
    <AttackPathGraphLegend model={model} />
  </>;
}

/**
 * The selected exposure path as a layered graph: the path is the spine, other
 * recorded paths that touch it branch off the shared node, and findings are
 * badges on the asset they affect rather than the last hop.
 */
export function AttackPathGraph(props: AttackPathGraphProps) {
  return (
    <div data-testid="attack-path-graph" className="overflow-hidden rounded-b-2xl">
      {props.toolbar}
      <ReactFlowProvider>
        <AttackPathCanvas {...props} />
      </ReactFlowProvider>
    </div>
  );
}
