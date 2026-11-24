"use client";

import { COMPACT_GLYPH_SCALE } from "@/lib/graph-compact-glyph";
import type { LineageNodeData, LineageNodeType } from "@/components/lineage-nodes";
import { CompactHandles } from "@/components/graph-compact-node";
import { entityIcon } from "@/lib/entity-icons";

const GLYPH = `calc(var(--graph-node-glyph-size, 56px) * ${COMPACT_GLYPH_SCALE})`;
const ICON = `calc(var(--graph-node-icon-size, 28px) * ${COMPACT_GLYPH_SCALE})`;

/** Siblings folded into one compact group: a circle, the group's name, and an expand line. */
export function CompactClusterNode({ data }: { data: LineageNodeData }) {
  const cluster = data as LineageNodeData & { count?: number; childType?: LineageNodeType };
  const count = cluster.count ?? 0;
  const childType = (cluster.childType ?? cluster.nodeType) as LineageNodeType;
  const Icon = entityIcon(childType);
  return <div data-testid="cluster-pill" data-cluster-count={count} data-graph-entity="cluster" title="Click to expand"
    className="relative mx-auto flex w-fit cursor-pointer flex-col items-center text-center" style={{ maxWidth: "var(--graph-node-card-width, 200px)" }}>
    <button type="button" aria-label={`Expand ${count} ${childType === "vulnerability" ? "findings" : "members"}`}
      className="nodrag nopan flex flex-col items-center rounded-lg focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-ring">
      <div className="graph-entity-glyph relative flex items-center justify-center rounded-full border-2 border-dashed border-outline-strong bg-surface" style={{ width: GLYPH, height: GLYPH }}>
        <CompactHandles data={data} source target />
        <Icon aria-hidden="true" className="text-ink-secondary" style={{ width: ICON, height: ICON }} />
      </div>
      <span className="mt-[0.3em] max-w-full truncate font-semibold leading-[1.15] text-foreground" style={{ fontSize: "calc(var(--graph-node-label-size, 14px) * 0.88)" }}>{data.label}</span>
      <span className="leading-[1.15] text-ink-secondary" style={{ fontSize: "var(--graph-node-meta-size, 12px)" }}>expand</span>
    </button>
  </div>;
}
