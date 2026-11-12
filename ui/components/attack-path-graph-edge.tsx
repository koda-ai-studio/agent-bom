"use client";

import { BaseEdge, EdgeLabelRenderer, getBezierPath, type Edge, type EdgeProps } from "@xyflow/react";

import type { EdgeEvidenceStyle, PathGraphEdge } from "@/lib/attack-path-graph-model";

export type AttackPathEdgeData = { edge: PathGraphEdge; active: boolean; markerPrefix: string; vertical: boolean };
export type AttackPathFlowEdge = Edge<AttackPathEdgeData, "attackPathEdge">;

export const LINE_STYLE: Record<EdgeEvidenceStyle, { name: "solid" | "dashed" | "dotted"; dash?: string }> = {
  recorded: { name: "solid" },
  inferred: { name: "dashed", dash: "7 5" },
  unrecorded: { name: "dotted", dash: "1.5 5" },
};

export function edgeStroke(onPath: boolean): string {
  return onPath ? "var(--accent)" : "var(--text-tertiary)";
}

export function AttackPathGraphEdge({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data }: EdgeProps<AttackPathFlowEdge>) {
  const [path, labelX, labelY] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition });
  if (!data) return null;
  const { edge, active, markerPrefix, vertical } = data;
  // Beside the line, clear of the glyphs: above it in a row, to its right in a column.
  const placement = vertical ? `translate(14px, -50%) translate(${labelX}px, ${labelY}px)` : `translate(-50%, -100%) translate(${labelX}px, ${labelY - 34}px)`;
  const style = LINE_STYLE[edge.evidence];
  const marker = `url(#${markerPrefix}-${edge.onPath ? "path" : "branch"})`;
  return <>
    <BaseEdge id={id} path={path} interactionWidth={18} data-line-style={style.name}
      markerEnd={marker} {...(edge.bidirectional ? { markerStart: marker } : {})}
      style={{
        stroke: edgeStroke(edge.onPath),
        strokeWidth: (edge.onPath ? 2.25 : 1.5) + (active ? 0.75 : 0),
        strokeDasharray: style.dash,
        strokeLinecap: style.name === "dotted" ? "round" : undefined,
      }} />
    {active && <EdgeLabelRenderer>
      <div role="tooltip" className="nodrag nopan pointer-events-none absolute z-20 whitespace-nowrap rounded-md border border-outline-strong bg-surface px-2 py-0.5 text-xs font-medium text-foreground shadow-md"
        style={{ transform: placement }}>
        {edge.relationshipLabel}
      </div>
    </EdgeLabelRenderer>}
  </>;
}

/** Arrowheads coloured by the same tokens as their lines, in both themes. */
export function AttackPathArrowDefs({ prefix }: { prefix: string }) {
  return (
    <svg aria-hidden="true" width="0" height="0" className="absolute">
      <defs>
        {(["path", "branch"] as const).map(kind => (
          <marker key={kind} id={`${prefix}-${kind}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" style={{ fill: edgeStroke(kind === "path") }} />
          </marker>
        ))}
      </defs>
    </svg>
  );
}

export const attackPathEdgeTypes = { attackPathEdge: AttackPathGraphEdge };
