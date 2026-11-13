"use client";

import { BaseEdge, EdgeLabelRenderer, type Edge, type EdgeProps } from "@xyflow/react";

import type { AttackPathDirection } from "@/lib/attack-path-graph-layout";
import type { EdgeEvidenceStyle, PathGraphEdge } from "@/lib/attack-path-graph-model";
import { routeLabelPoint, routePath, type Point } from "@/lib/attack-path-graph-routes";

export type AttackPathEdgeData = { edge: PathGraphEdge; active: boolean; markerPrefix: string; direction: AttackPathDirection; route: Point[] };
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
  const { edge, active, markerPrefix, direction, route } = data;
  const style = LINE_STYLE[edge.evidence];
  const stroke = edge.onPath ? PATH_STROKE.selected : PATH_STROKE.connected;
  const kind = edge.onPath ? "path" : "branch";
  // A two-way relationship has no direction to show: dots at both ends instead of arrowheads.
  const ends = edge.bidirectional
    ? { markerStart: `url(#${markerPrefix}-dot-${kind})`, markerEnd: `url(#${markerPrefix}-dot-${kind})` }
    : { markerEnd: `url(#${markerPrefix}-${kind})` };
  const label = routeLabelPoint(route);
  const placement = direction === "TB"
    ? `translate(14px, -50%) translate(${label.x}px, ${label.y}px)`
    : `translate(-50%, -100%) translate(${label.x}px, ${label.y - 14}px)`;
  return <>
    <BaseEdge id={id} path={routePath(route, direction)} interactionWidth={18} data-line-style={style.name} data-two-way={edge.bidirectional || undefined} {...ends}
      style={{
        stroke: stroke.color,
        strokeWidth: stroke.width + (active ? 0.75 : 0),
        strokeDasharray: style.dash,
        strokeLinecap: style.name === "dotted" ? "round" : undefined,
      }} />
    {active && <EdgeLabelRenderer>
      <div role="tooltip" className="nodrag nopan pointer-events-none absolute z-20 whitespace-nowrap rounded-md border border-outline-strong bg-surface px-2 py-0.5 text-xs font-medium text-foreground shadow-md"
        style={{ transform: placement }}>
        {edge.relationshipLabel}{edge.bidirectional ? " · two-way" : ""}
      </div>
    </EdgeLabelRenderer>}
  </>;
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
