"use client";

import { BaseEdge, EdgeLabelRenderer, type Edge, type EdgeProps } from "@xyflow/react";

import type { AttackPathDirection } from "@/lib/attack-path-graph-layout";
import { routeLabelPoint, routePath, type Point } from "@/lib/attack-path-graph-routes";
import type { ArchitectureEdge, ArchitectureEdgeKind } from "@/lib/agent-architecture-model";

export type ArchitectureEdgeData = { edge: ArchitectureEdge; active: boolean; markerPrefix: string; direction: AttackPathDirection; route: Point[] };
export type ArchitectureFlowEdge = Edge<ArchitectureEdgeData, "architectureEdge">;

type Stroke = { color: string; width: number; dash?: string; round?: boolean; arrow: "accent" | "muted" };

/** One style per edge kind, used by both layouts and the legend. */
export const EDGE_STYLE: Record<ArchitectureEdgeKind, Stroke> = {
  entry: { color: "var(--accent)", width: 2.25, arrow: "accent" },
  handoff: { color: "var(--accent)", width: 1.75, dash: "10 4 2 4", arrow: "accent" },
  sequential: { color: "var(--text-secondary)", width: 1.5, arrow: "muted" },
  conditional: { color: "var(--text-secondary)", width: 1.5, dash: "7 5", arrow: "muted" },
  fan_out: { color: "var(--text-secondary)", width: 1.5, dash: "1.5 5", round: true, arrow: "muted" },
  subgraph: { color: "var(--text-secondary)", width: 2.25, arrow: "muted" },
  finish: { color: "var(--text-tertiary)", width: 1.25, arrow: "muted" },
  member: { color: "var(--border-strong)", width: 1.25, arrow: "muted" },
  contains: { color: "var(--border-strong)", width: 1.25, arrow: "muted" },
  unresolved: { color: "var(--text-tertiary)", width: 1.25, dash: "3 4", arrow: "muted" },
};

export function ArchitectureGraphEdge({ id, data }: EdgeProps<ArchitectureFlowEdge>) {
  if (!data) return null;
  const { edge, active, markerPrefix, direction, route } = data;
  const style = EDGE_STYLE[edge.kind];
  const label = routeLabelPoint(route);
  const placement = direction === "TB"
    ? `translate(14px, -50%) translate(${label.x}px, ${label.y}px)`
    : `translate(-50%, -100%) translate(${label.x}px, ${label.y - 14}px)`;
  return <>
    <BaseEdge id={id} path={routePath(route)} interactionWidth={18} data-edge-kind={edge.kind}
      markerEnd={`url(#${markerPrefix}-${style.arrow})`}
      style={{ stroke: style.color, strokeWidth: style.width + (active ? 0.75 : 0), strokeDasharray: style.dash, strokeLinecap: style.round ? "round" : undefined }} />
    {active && <EdgeLabelRenderer>
      <div role="tooltip" className="nodrag nopan pointer-events-none absolute z-20 whitespace-nowrap rounded-md border border-outline-strong bg-surface px-2 py-0.5 text-xs font-medium text-foreground shadow-md"
        style={{ transform: placement }}>
        {edge.description}
      </div>
    </EdgeLabelRenderer>}
  </>;
}

export function ArchitectureArrowDefs({ prefix }: { prefix: string }) {
  return (
    <svg aria-hidden="true" width="0" height="0" className="absolute">
      <defs>
        {([["accent", "var(--accent)"], ["muted", "var(--text-secondary)"]] as const).map(([name, fill]) => (
          <marker key={name} id={`${prefix}-${name}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" style={{ fill }} />
          </marker>
        ))}
      </defs>
    </svg>
  );
}

export const architectureEdgeTypes = { architectureEdge: ArchitectureGraphEdge };
