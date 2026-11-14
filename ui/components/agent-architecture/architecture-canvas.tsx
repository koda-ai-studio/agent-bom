"use client";

import { Background, Position, ReactFlow, ReactFlowProvider } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useId, useMemo, useRef, useState } from "react";

import { ArchitectureArrowDefs, architectureEdgeTypes, type ArchitectureFlowEdge } from "@/components/agent-architecture/architecture-edge";
import { architectureNodeTypes, findingsLabel, type ArchitectureFlowNode } from "@/components/agent-architecture/architecture-node";
import { GraphCamera, HIT_AREAS, OVERVIEW_MIN_ZOOM } from "@/components/attack-path-graph";
import { useElementWidth } from "@/hooks/use-element-width";
import { useWheelZoomGate, WheelZoomHint } from "@/hooks/use-wheel-zoom-gate";
import { architectureCanvasHeight, layoutArchitecture, routeArchitecture } from "@/lib/agent-architecture-layout";
import type { ArchitectureModel } from "@/lib/agent-architecture-model";
import { PATH_DESKTOP_MIN_ZOOM } from "@/lib/attack-path-graph-layout";
import { GLYPH_CENTER_Y, glyphInsetX } from "@/lib/attack-path-graph-routes";
import { activateGraphNodeFromKeyboard } from "@/lib/graph-keyboard-selection";
import { BACKGROUND_GAP } from "@/lib/graph-utils";

type Props = { model: ArchitectureModel; onOpen: (nodeId: string) => void; onExpand: (groupId: string) => void };

function edgeFromTarget(target: EventTarget | null): string | null {
  return target instanceof Element ? target.closest(".react-flow__edge")?.getAttribute("data-id") ?? null : null;
}

function useElements(model: ArchitectureModel, activeEdge: string | null, markerPrefix: string, handlers: Pick<Props, "onOpen" | "onExpand">) {
  const layout = useMemo(() => layoutArchitecture(model), [model]);
  const routes = useMemo(() => routeArchitecture(model, layout), [layout, model]);
  const vertical = layout.direction === "TB";
  const inset = glyphInsetX(layout.nodeWidth);
  const nodes = useMemo<ArchitectureFlowNode[]>(() => model.nodes.map(node => ({
    id: node.id, type: "architectureNode", position: layout.positions.get(node.id)!, width: layout.nodeWidth, height: layout.nodeHeight,
    handles: vertical
      ? [{ type: "target" as const, position: Position.Top, x: layout.nodeWidth / 2, y: 0, width: 1, height: 1, id: null },
        { type: "source" as const, position: Position.Bottom, x: layout.nodeWidth / 2, y: layout.nodeHeight, width: 1, height: 1, id: null }]
      : [{ type: "target" as const, position: Position.Left, x: inset, y: GLYPH_CENTER_Y, width: 1, height: 1, id: null },
        { type: "source" as const, position: Position.Right, x: layout.nodeWidth - inset, y: GLYPH_CENTER_Y, width: 1, height: 1, id: null }],
    ariaLabel: `${node.label}, ${node.subtitle}${node.entry ? ", entry" : ""}${node.findings ? `, ${findingsLabel(node)}` : ""}`,
    data: { node, vertical, ...handlers },
  })), [handlers, inset, layout, model.nodes, vertical]);
  const labels = useMemo(() => new Map(model.nodes.map(node => [node.id, node.label])), [model.nodes]);
  const edges = useMemo<ArchitectureFlowEdge[]>(() => model.edges.map(edge => ({
    id: edge.id, source: edge.source, target: edge.target, type: "architectureEdge",
    ariaLabel: `${labels.get(edge.source)} to ${labels.get(edge.target)}: ${edge.description}`,
    data: { edge, active: edge.id === activeEdge, markerPrefix, direction: layout.direction, route: routes.get(edge.id)! },
  })), [activeEdge, labels, layout.direction, markerPrefix, model.edges, routes]);
  return { layout, nodes, edges };
}

function Canvas({ model, onOpen, onExpand }: Props) {
  const [activeEdge, setActiveEdge] = useState<string | null>(null);
  const markerPrefix = `arch${useId().replaceAll(":", "")}`;
  const wheelGate = useWheelZoomGate();
  const handlers = useMemo(() => ({ onOpen, onExpand }), [onExpand, onOpen]);
  const { layout, nodes, edges } = useElements(model, activeEdge, markerPrefix, handlers);
  const frameRef = useRef<HTMLDivElement>(null);
  const height = architectureCanvasHeight(layout, useElementWidth(frameRef));
  const nodesKey = `${model.mode}:${nodes.map(node => node.id).join("|")}`;
  const manualCamera = useRef<string | null>(null);
  // A layered map has no single spine: the camera keeps the whole tree centred. A flow frames its harness and entries.
  const spine = useMemo(() => model.nodes.filter(node => model.mode === "layered" || node.id === model.rootId || node.entry).map(node => node.id), [model]);
  return (
    <div ref={frameRef} className={`relative bg-surface ${HIT_AREAS}`} style={{ height }} data-testid="architecture-canvas" data-layout={model.mode}
      onFocusCapture={event => { const id = edgeFromTarget(event.target); if (id) setActiveEdge(id); }}
      onBlurCapture={event => { if (edgeFromTarget(event.target)) setActiveEdge(null); }}
      onKeyDownCapture={event => { activateGraphNodeFromKeyboard(event); }}
      {...wheelGate.handlers}>
      <ArchitectureArrowDefs prefix={markerPrefix} />
      <WheelZoomHint visible={wheelGate.hintVisible} />
      <ReactFlow<ArchitectureFlowNode, ArchitectureFlowEdge>
        nodes={nodes} edges={edges} nodeTypes={architectureNodeTypes} edgeTypes={architectureEdgeTypes}
        minZoom={OVERVIEW_MIN_ZOOM} maxZoom={2}
        zoomOnScroll={wheelGate.armed} preventScrolling={wheelGate.armed} zoomOnPinch panOnDrag
        nodesDraggable={false} nodesConnectable={false} nodesFocusable edgesFocusable elementsSelectable deleteKeyCode={null}
        onNodeClick={(_, node) => { if (node.data.node.kind === "group") onExpand(node.id); else onOpen(node.id); }}
        onEdgeMouseEnter={(_, edge) => setActiveEdge(edge.id)}
        onEdgeMouseLeave={() => setActiveEdge(null)}
        onMoveStart={event => { if (event) manualCamera.current = nodesKey; }}
        proOptions={{ hideAttribution: true }}>
        <Background gap={BACKGROUND_GAP} color="var(--border-subtle)" />
        <GraphCamera layout={layout} spineIds={spine} nodesKey={nodesKey} floor={PATH_DESKTOP_MIN_ZOOM} manual={manualCamera} />
      </ReactFlow>
    </div>
  );
}

/** The harness on the shared graph canvas: attack-path layout geometry, routing and camera. */
export function ArchitectureCanvas(props: Props) {
  return <ReactFlowProvider><Canvas {...props} /></ReactFlowProvider>;
}
