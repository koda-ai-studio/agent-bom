"use client";

import { useMemo } from "react";
import type { Edge } from "@xyflow/react";
import { flowEdgeLegend, type FlowLineStyle } from "@/lib/graph-flow-legend";

const STYLE_LABELS: Record<FlowLineStyle, string> = {
  solid: "Recorded relationship",
  modeled: "Links modeled from scan evidence",
  dashed: "Modeled relationship",
  unknown: "Evidence unavailable",
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
  const exposure = useMemo(() => edges.some(edge => edge.data?.exposurePath === true), [edges]);
  if (!legend.styles.length) return null;

  const item = "inline-flex items-center gap-1.5";
  return (
    <ul aria-label="Line legend" data-testid="graph-flow-edge-legend" className="flex flex-wrap items-center gap-x-4 gap-y-1.5 border-t border-outline bg-surface px-3 py-2 text-xs text-ink-secondary">
      {exposure && <li className={item} data-legend-exposure-path=""><Swatch stroke="var(--graph-edge-exposure)" />Exposure path from the Internet</li>}
      {legend.styles.map(style => (
        <li key={style} className={item}><Swatch dash={style === "dashed" ? "6 3" : style === "unknown" ? "1.5 5" : style === "runtime" ? "2 3" : undefined} />{STYLE_LABELS[style]}</li>
      ))}
      <li className={item}>Finding count · highest severity:
        {[["Critical", "var(--severity-ring-critical)"], ["High", "#a63e08"], ["Medium", "#806100"], ["Low", "var(--severity-ring-low)"]].map(([label, color]) => <span key={label} className={item}><span aria-hidden="true" className="inline-block h-2 w-2 rounded-full" style={{background: color}} />{label}</span>)}
      </li>
      {legend.more > 0 && <li className="text-ink-tertiary">+{legend.more} more {legend.more === 1 ? "relationship" : "relationships"} · hover a line for its name</li>}
    </ul>
  );
}
