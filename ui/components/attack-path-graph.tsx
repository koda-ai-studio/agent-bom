"use client";

import { Background, ControlButton, Controls, ReactFlow, ReactFlowProvider, getViewportForBounds, useReactFlow, useStore, Position, type Rect } from "@xyflow/react";
import { Maximize } from "lucide-react";
import "@xyflow/react/dist/style.css";
import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";

import { AttackPathArrowDefs, attackPathEdgeTypes, type AttackPathFlowEdge } from "@/components/attack-path-graph-edge";
import { AttackPathGraphLegend } from "@/components/attack-path-graph-legend";
import { GLYPH_CENTER_Y, GLYPH_INSET_X, attackPathNodeTypes, type AttackPathFlowNode } from "@/components/attack-path-graph-node";
import { useElementWidth } from "@/hooks/use-element-width";
import { activateGraphNodeFromKeyboard } from "@/lib/graph-keyboard-selection";
import { useWheelZoomGate, WheelZoomHint } from "@/hooks/use-wheel-zoom-gate";
import { DESKTOP_FIT_PADDING, DESKTOP_MIN_ZOOM, attackPathCanvasHeight, layoutAttackPathGraph, narrowFitZoom } from "@/lib/attack-path-graph-layout";
import { buildAttackPathGraphModel, type AttackPathGraphModel } from "@/lib/attack-path-graph-model";
import type { AttackPath, UnifiedGraphData } from "@/lib/graph-schema";
import { BACKGROUND_GAP, CONTROLS_CLASS } from "@/lib/graph-utils";

export type AttackPathGraphProps = {
  graph: UnifiedGraphData;
  attackPath: AttackPath;
  /** Phones stack the path top to bottom. */
  narrow: boolean;
  onNodeSelect: (nodeId: string) => void;
  onEdgeSelect: (edge: { id: string; source: string; target: string; relationship: string }) => void;
  onOpenFindings: (nodeId: string, findingIds: string[]) => void;
  /** Toolbar row rendered above the canvas (focus toggle, lineage, fullscreen). */
  toolbar?: React.ReactNode;
};

type FitOptions = { padding: number | { x: `${number}px`; y: `${number}px` }; minZoom: number; maxZoom: number };
/** Only a node's glyph, label and buttons take pointer input; its empty box never swallows a click meant for a line. */
const HIT_AREAS = "[&_[aria-roledescription=node]]:pointer-events-none! [&_[data-node-glyph]]:pointer-events-auto! [&_[data-node-label]]:pointer-events-auto! [&_[aria-roledescription=node]_button]:pointer-events-auto!";
const DESKTOP_FIT: FitOptions = { padding: DESKTOP_FIT_PADDING, minZoom: DESKTOP_MIN_ZOOM, maxZoom: 1 };

/**
 * Frame the laid-out graph in the measured pane. React Flow 12 queues
 * `fitView()` until the next node update, so a canvas resize alone would keep
 * the previous camera; the viewport is computed from the layout bounds instead.
 */
function useFitToLayout(bounds: Rect, fit: FitOptions) {
  const { setViewport } = useReactFlow();
  const paneWidth = useStore(state => state.width);
  const paneHeight = useStore(state => state.height);
  const fitNow = useCallback(() => {
    if (!paneWidth || !paneHeight) return;
    void setViewport(getViewportForBounds(bounds, paneWidth, paneHeight, fit.minZoom, fit.maxZoom, fit.padding));
  }, [bounds, fit, paneHeight, paneWidth, setViewport]);
  return fitNow;
}

/** Auto-fit on layout or canvas changes, unless the operator has moved this node set's camera. */
function FitOnLayout({ bounds, nodesKey, fit, manual }: { bounds: Rect; nodesKey: string; fit: FitOptions; manual: React.RefObject<string | null> }) {
  const fitNow = useFitToLayout(bounds, fit);
  useEffect(() => {
    if (manual.current !== nodesKey) fitNow();
  }, [fitNow, manual, nodesKey]);
  return <Controls className={CONTROLS_CLASS} showInteractive={false} showFitView={false} orientation="horizontal" position="top-right">
    <ControlButton className="react-flow__controls-fitview" title="fit view" aria-label="fit view"
      onClick={() => { manual.current = null; fitNow(); }}>
      <Maximize aria-hidden="true" />
    </ControlButton>
  </Controls>;
}

function edgeFromTarget(target: EventTarget | null): string | null {
  return target instanceof Element ? target.closest(".react-flow__edge")?.getAttribute("data-id") ?? null : null;
}

function useFlowElements(model: AttackPathGraphModel, narrow: boolean, activeEdge: string | null, markerPrefix: string,
  handlers: { onOpenFindings: AttackPathGraphProps["onOpenFindings"]; onExpandGroup: (id: string) => void }) {
  const layout = useMemo(() => layoutAttackPathGraph(model, narrow ? "TB" : "LR"), [model, narrow]);
  const nodes = useMemo<AttackPathFlowNode[]>(() => model.nodes.map(node => {
    const handles = narrow
      ? [{ type: "target" as const, position: Position.Top, x: layout.nodeWidth / 2, y: 0, width: 1, height: 1, id: null },
        { type: "source" as const, position: Position.Bottom, x: layout.nodeWidth / 2, y: layout.nodeHeight, width: 1, height: 1, id: null }]
      : [{ type: "target" as const, position: Position.Left, x: GLYPH_INSET_X, y: GLYPH_CENTER_Y, width: 1, height: 1, id: null },
        { type: "source" as const, position: Position.Right, x: layout.nodeWidth - GLYPH_INSET_X, y: GLYPH_CENTER_Y, width: 1, height: 1, id: null }];
    return {
      id: node.id, type: "attackPathNode", position: layout.positions.get(node.id)!,
      width: layout.nodeWidth, height: layout.nodeHeight, handles,
      ariaLabel: `${node.label}, ${node.typeLabel}${node.findings.length ? `, ${node.findings.length} findings` : ""}`,
      data: { node, vertical: narrow, ...handlers },
    };
  }), [handlers, layout, model.nodes, narrow]);
  const labels = useMemo(() => new Map(model.nodes.map(node => [node.id, node.label])), [model.nodes]);
  const edges = useMemo<AttackPathFlowEdge[]>(() => model.edges.map(edge => ({
    id: edge.id, source: edge.source, target: edge.target, type: "attackPathEdge",
    ariaLabel: `${labels.get(edge.source)} ${edge.relationshipLabel.toLowerCase()} ${labels.get(edge.target)}`,
    data: { edge, active: edge.id === activeEdge, markerPrefix, vertical: narrow },
  })), [activeEdge, labels, markerPrefix, model.edges, narrow]);
  return { layout, nodes, edges };
}

function AttackPathCanvas({ graph, attackPath, narrow, onNodeSelect, onEdgeSelect, onOpenFindings }: AttackPathGraphProps) {
  const [expandedGroups, setExpandedGroups] = useState<ReadonlySet<string>>(new Set());
  const [activeEdge, setActiveEdge] = useState<string | null>(null);
  const markerPrefix = `apg${useId().replaceAll(":", "")}`;
  const wheelGate = useWheelZoomGate();
  const model = useMemo(() => buildAttackPathGraphModel(graph, attackPath, { expandedGroups }), [attackPath, expandedGroups, graph]);
  const onExpandGroup = useCallback((id: string) => setExpandedGroups(current => new Set([...current, id])), []);
  const handlers = useMemo(() => ({ onOpenFindings, onExpandGroup }), [onExpandGroup, onOpenFindings]);
  const { layout, nodes, edges } = useFlowElements(model, narrow, activeEdge, markerPrefix, handlers);
  const frameRef = useRef<HTMLDivElement>(null);
  const frameWidth = useElementWidth(frameRef);
  const height = attackPathCanvasHeight(layout, narrow, frameWidth);
  const zoom = narrow ? narrowFitZoom(layout, frameWidth) : 1;
  const fit = useMemo<FitOptions>(() => narrow ? { padding: { x: "8px", y: "16px" }, minZoom: zoom, maxZoom: 1 } : DESKTOP_FIT, [narrow, zoom]);
  const nodesKey = nodes.map(node => node.id).join("|");
  const bounds = useMemo<Rect>(() => ({ x: 0, y: 0, width: layout.width, height: layout.height }), [layout.height, layout.width]);
  const manualCamera = useRef<string | null>(null);
  // Collapsed-group links stand in for several records; only a recorded edge has a receipt.
  const openEdge = (edge: AttackPathFlowEdge) => {
    if (graph.edges.some(item => item.id === edge.id)) onEdgeSelect({ id: edge.id, source: edge.source, target: edge.target, relationship: edge.data!.edge.relationship });
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
        minZoom={0.35} maxZoom={2}
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
        <FitOnLayout bounds={bounds} nodesKey={nodesKey} fit={fit} manual={manualCamera} />
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
