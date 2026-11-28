"use client";

import { EDGE_STROKE } from "@/lib/graph-edge-family";
import { BaseEdge, EdgeLabelRenderer, Position, useStore, type Edge, type EdgeProps } from "@xyflow/react";

import type { AttackPathDirection } from "@/lib/attack-path-graph-layout";
import { compactEdgeCurve } from "@/components/graph-compact-edge";
import type { EdgeEvidenceStyle, PathGraphEdge } from "@/lib/attack-path-graph-model";
import { relationshipLaneFor } from "@/lib/relationship-lanes";
import { relationshipPath } from "@/lib/relationship-routing";
import type { HopTrace } from "@/lib/attack-path-trace";

/** One hop of the single entry-to-target trace drawn when a path is selected; absent under reduced motion. */
export type EdgeTrace = HopTrace & { index: number; key: string };
export type AttackPathEdgeData = { edge: PathGraphEdge; active: boolean; markerPrefix: string; direction: AttackPathDirection; trace?: EdgeTrace | null };
export type AttackPathFlowEdge = Edge<AttackPathEdgeData, "attackPathEdge">;

export const LINE_STYLE: Record<EdgeEvidenceStyle, { name: "solid" | "dashed" | "dotted"; dash?: string }> = {
  receipt: { name: "solid" },
  recorded: { name: "solid" },
  inferred: { name: "dashed", dash: "7 5" },
  unrecorded: { name: "dotted", dash: "1.5 5" },
};

/** The selected path reads first: thick accent. Connected paths recede: thin and muted. */
export const PATH_STROKE = { selected: { color: "var(--graph-edge-exposure)", width: EDGE_STROKE.path }, connected: { color: "var(--graph-edge-structure)", width: EDGE_STROKE.rest } } as const;

export function edgeStroke(onPath: boolean): string {
  return (onPath ? PATH_STROKE.selected : PATH_STROKE.connected).color;
}

/** Two cards of one column on a row layout: one C-curve from the lower card's right rim to the other's, bowing right
 * of both glyphs and the names under them. */
export function sideArcPath(source: { x: number; y: number }, target: { x: number; y: number }): string {
  const reach = Math.max(80, Math.abs(target.y - source.y) * 0.35);
  return `M${source.x},${source.y} C${source.x + reach},${source.y} ${target.x + reach},${target.y} ${target.x},${target.y}`;
}

export function AttackPathGraphEdge(props: EdgeProps<AttackPathFlowEdge>) {
  const { id, data } = props;
  const edges = useStore(state => state.edges);
  const nodes = useStore(state => state.nodes);
  if (!data) return null;
  const { edge, active, markerPrefix, direction, trace } = data;
  const style = LINE_STYLE[edge.evidence];
  const stroke = edge.onPath ? PATH_STROKE.selected : PATH_STROKE.connected;
  const kind = edge.onPath ? "path" : "branch";
  // A two-way relationship has no direction to show: dots at both ends instead of arrowheads.
  const ends = edge.bidirectional
    ? { markerStart: `url(#${markerPrefix}-dot-${kind})`, markerEnd: `url(#${markerPrefix}-dot-${kind})` }
    : { markerEnd: `url(#${markerPrefix}-${kind})` };
  const lane = relationshipLaneFor(id, edges, nodeId => nodes.find(node => node.id === nodeId)?.position.y,
    nodeId => nodes.find(node => node.id === nodeId)?.position.x);
  // A phone column draws one smooth curve between the two handles; routing around obstacles there looped past the column.
  const sideArc = direction === "LR" && props.sourcePosition === Position.Right && props.targetPosition === Position.Right && Math.abs(props.sourceX - props.targetX) < 1;
  // A branch into a lower lane of a later column drops once, between the caption columns, instead of riding the path line.
  const drop = direction === "LR" && !edge.onPath && props.targetX - props.sourceX > 40 && props.targetY - props.sourceY > 40;
  const bend = props.sourceX + 0.7 * (props.targetX - props.sourceX);
  const curve = direction === "TB" ? compactEdgeCurve(props)
    : drop ? { path: `M${props.sourceX},${props.sourceY} C${bend},${props.sourceY} ${bend},${props.targetY} ${props.targetX},${props.targetY}`,
      mid: { x: (props.sourceX + props.targetX) / 2, y: (props.sourceY + props.targetY) / 2 } }
    : sideArc ? { path: sideArcPath({ x: props.sourceX, y: props.sourceY }, { x: props.targetX, y: props.targetY }),
      mid: { x: props.sourceX + 0.75 * Math.max(80, Math.abs(props.targetY - props.sourceY) * 0.35), y: (props.sourceY + props.targetY) / 2 } } : null;
  const [path, labelX, labelY] = curve ? [curve.path, curve.mid.x, curve.mid.y] : relationshipPath(props, nodes.filter(node => !node.hidden).map(node => ({ id: node.id, ...node.position,
    width: node.measured?.width ?? node.width ?? 152, height: node.measured?.height ?? node.height ?? 136 })), lane);
  const label = { x: labelX, y: labelY };
  // On a row a selected-path hop names its relationship on the line at all times (lines that turn into branch
  // rows leave below it). A phone column has no room beside the line, so there every link names itself on hover or focus.
  const transform = direction === "TB"
    ? `translate(10px, -50%) translate(${label.x}px, ${label.y}px)`
    // An inspected link's tooltip clears the 56px glyphs it joins, however short the link between them is.
    : `translate(-50%, -100%) translate(${label.x}px, ${label.y - (active ? 34 : 4)}px)`;
  return <>
    <BaseEdge id={id} path={path} interactionWidth={18} data-line-style={style.name} data-two-way={edge.bidirectional || undefined} {...ends}
      style={{
        stroke: edge.relationship === "can_access" ? "var(--graph-edge-risk)" : stroke.color,
        strokeWidth: stroke.width + (active ? 0.75 : 0),
        strokeDasharray: style.dash,
        strokeLinecap: style.name === "dotted" ? "round" : undefined,
      }} />
    {trace && !edge.displayOnly && <path key={trace.key} data-path-trace={trace.index} d={path} pathLength={1} aria-hidden="true"
      className="attack-path-trace" style={{ animationDuration: `${trace.duration}ms`, animationDelay: `${trace.delay}ms` }} />}
    {(active || edge.relationship === "can_access") && <EdgeName active={active} transform={transform}
      text={`${edge.relationshipLabel}${active && edge.bidirectional ? " · two-way" : ""}`}
      room={direction === "TB" || active ? 0 : Math.abs(props.targetX - props.sourceX) - 12} />}
  </>;
}

/** The relationship name, about 11px on screen at any zoom the camera allows; raised as a tooltip while inspected. */
function EdgeName({ text, transform, room, active }: { text: string; transform: string; room: number; active: boolean }) {
  const zoom = useStore(state => state.transform[2]);
  return <EdgeLabelRenderer>
    <div role={active ? "tooltip" : undefined} data-path-hop-label={active ? undefined : ""} title={text}
      className={`nodrag nopan pointer-events-none absolute truncate whitespace-nowrap rounded px-1 font-medium leading-tight ${active ? "z-20 border border-outline-strong bg-surface text-foreground shadow-md" : "bg-surface/90 text-ink-secondary"}`}
      style={{ transform, fontSize: Math.max(11, 11 / Math.max(zoom, 0.25)), maxWidth: room > 0 ? Math.max(48, room) : undefined }}>
      {text}
    </div>
  </EdgeLabelRenderer>;
}

/** Arrowheads and two-way dots coloured by the same tokens as their lines, in both themes. */
export function AttackPathArrowDefs({ prefix }: { prefix: string }) {
  return (
    <svg aria-hidden="true" width="0" height="0" className="absolute">
      <defs>
        {(["path", "branch"] as const).map(kind => (
          <g key={kind}>
            <marker id={`${prefix}-${kind}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" markerUnits="userSpaceOnUse" orient="auto-start-reverse">
              <path d="M0,0 L10,5 L0,10 z" style={{ fill: "context-stroke" }} />
            </marker>
            <marker id={`${prefix}-dot-${kind}`} viewBox="0 0 10 10" refX="5" refY="5" markerWidth="5" markerHeight="5" markerUnits="userSpaceOnUse">
              <circle cx="5" cy="5" r="4" style={{ fill: "context-stroke" }} />
            </marker>
          </g>
        ))}
      </defs>
    </svg>
  );
}

export const attackPathEdgeTypes = { attackPathEdge: AttackPathGraphEdge };
