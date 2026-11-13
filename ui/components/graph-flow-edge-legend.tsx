"use client";

import { useMemo } from "react";
import type { Edge } from "@xyflow/react";
import { flowEdgeLegend, type FlowLineStyle } from "@/lib/graph-flow-legend";

const STYLE_LABELS: Record<FlowLineStyle, string> = {
  solid: "Recorded relationship",
  dashed: "Modeled, or access not observed in use",
  runtime: "Moving line: runtime receipt",
};

function Swatch({ stroke = "var(--text-secondary)", dash }: { stroke?: string; dash?: string | undefined }) {
  return (
    <svg width="28" height="8" aria-hidden="true" className="shrink-0">
      <line x1="1" y1="4" x2="27" y2="4" style={{ stroke, strokeWidth: 2, strokeDasharray: dash }} />
    </svg>
  );
}

/** One line under the canvas saying what each drawn line style and colour means. */
export function GraphFlowEdgeLegend({ edges }: { edges: readonly Edge[] }) {
  const legend = useMemo(() => flowEdgeLegend(edges), [edges]);
  if (!legend.styles.length) return null;
  const item = "inline-flex items-center gap-1.5";
  return (
    <ul aria-label="Line legend" data-testid="graph-flow-edge-legend" className="flex flex-wrap items-center gap-x-4 gap-y-1.5 border-t border-outline bg-surface px-3 py-2 text-xs text-ink-secondary">
      {legend.styles.map(style => (
        <li key={style} className={item}><Swatch dash={style === "dashed" ? "6 3" : style === "runtime" ? "2 3" : undefined} />{STYLE_LABELS[style]}</li>
      ))}
      {legend.relationships.map(entry => (
        <li key={entry.relationship} className={item}><Swatch stroke={entry.stroke} />{entry.label}</li>
      ))}
      {legend.more > 0 && <li className="text-ink-tertiary">+{legend.more} more {legend.more === 1 ? "relationship" : "relationships"} · hover a line for its name</li>}
    </ul>
  );
}
