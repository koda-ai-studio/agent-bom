"use client";

import { BaseEdge, EdgeLabelRenderer, useStore, type Edge, type EdgeProps } from "@xyflow/react";

import type { AttackPathDirection } from "@/lib/attack-path-graph-layout";
import type { EdgeEvidenceStyle, PathGraphEdge } from "@/lib/attack-path-graph-model";
import { routeLabelPoint, routePath, type Point } from "@/lib/attack-path-graph-routes";
import type { HopTrace } from "@/lib/attack-path-trace";

/** One hop of the single entry-to-target trace drawn when a path is selected; absent under reduced motion. */
export type EdgeTrace = HopTrace & { index: number; key: string };
export type AttackPathEdgeData = { edge: PathGraphEdge; active: boolean; markerPrefix: string; direction: AttackPathDirection; route: Point[]; trace?: EdgeTrace | null };
export type AttackPathFlowEdge = Edge<AttackPathEdgeData, "attackPathEdge">;

export const LINE_STYLE: Record<EdgeEvidenceStyle, { name: "solid" | "dashed" | "dotted"; dash?: string }> = {
  receipt: { name: "solid" },
  recorded: { name: "solid" },
  inferred: { name: "dashed", dash: "7 5" },
  unrecorded: { name: "dotted", dash: "1.5 5" },
};

/** The selected path reads first: thick accent. Connected paths recede: thin and muted. */
export const PATH_STROKE = { selected: { color: "var(--accent)", width: 2.5 }, connected: { color: "var(--border-strong)", width: 1.25 } } as const;

export function edgeStroke(onPath: boolean): string {
  return (onPath ? PATH_STROKE.selected : PATH_STROKE.connected).color;
}

export function AttackPathGraphEdge({ id, data }: EdgeProps<AttackPathFlowEdge>) {
  if (!data) return null;
  const { edge, active, markerPrefix, direction, route, trace } = data;
  const style = LINE_STYLE[edge.evidence];
  const stroke = edge.onPath ? PATH_STROKE.selected : PATH_STROKE.connected;
  const kind = edge.onPath ? "path" : "branch";
  // A two-way relationship has no direction to show: dots at both ends instead of arrowheads.
  const ends = edge.bidirectional
    ? { markerStart: `url(#${markerPrefix}-dot-${kind})`, markerEnd: `url(#${markerPrefix}-dot-${kind})` }
    : { markerEnd: `url(#${markerPrefix}-${kind})` };
  const label = routeLabelPoint(route);
  // A selected-path hop names its relationship on the line at all times: above it on a row (lines that turn
  // into branch rows leave below it) and beside it on a phone column. A branch names its own on hover or focus.
  const transform = direction === "TB"
    ? `translate(10px, -50%) translate(${label.x}px, ${label.y}px)`
    : `translate(-50%, -100%) translate(${label.x}px, ${label.y - 4}px)`;
  return <>
    <BaseEdge id={id} path={routePath(route)} interactionWidth={18} data-line-style={style.name} data-two-way={edge.bidirectional || undefined} {...ends}
      style={{
        stroke: stroke.color,
        strokeWidth: stroke.width + (active ? 0.75 : 0),
        strokeDasharray: style.dash,
        strokeLinecap: style.name === "dotted" ? "round" : undefined,
      }} />
    {trace && <path key={trace.key} data-path-trace={trace.index} d={routePath(route)} pathLength={1} aria-hidden="true"
      className="attack-path-trace" style={{ animationDuration: `${trace.duration}ms`, animationDelay: `${trace.delay}ms` }} />}
    {(active || edge.onPath) && <EdgeName active={active} transform={transform}
      text={`${edge.relationshipLabel}${active && edge.bidirectional ? " · two-way" : ""}`}
      room={direction === "TB" || active ? 0 : Math.abs(route.at(-1)!.x - route[0]!.x) - 12} />}
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
            <marker id={`${prefix}-${kind}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0,0 L10,5 L0,10 z" style={{ fill: edgeStroke(kind === "path") }} />
            </marker>
            <marker id={`${prefix}-dot-${kind}`} viewBox="0 0 10 10" refX="5" refY="5" markerWidth="5" markerHeight="5">
              <circle cx="5" cy="5" r="4" style={{ fill: edgeStroke(kind === "path") }} />
            </marker>
          </g>
        ))}
      </defs>
    </svg>
  );
}

export const attackPathEdgeTypes = { attackPathEdge: AttackPathGraphEdge };
