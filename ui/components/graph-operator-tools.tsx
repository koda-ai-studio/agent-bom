"use client";

import dynamic from "next/dynamic";

import type { GraphEdgeChangesResponse } from "@/lib/api";
import type { DriftLensFilter, EvidenceLensFilter } from "@/lib/filter-algebra";
import type { ChangeKind, driftAttributeSummaries } from "@/lib/graph-utils";

const GraphDriftLegend = dynamic(() => import("@/components/graph-lens-legends").then(mod => mod.GraphDriftLegend), { ssr: false });
const GraphEvidenceLegend = dynamic(() => import("@/components/graph-lens-legends").then(mod => mod.GraphEvidenceLegend), { ssr: false });
const GraphEdgeChangesPanel = dynamic(() => import("@/components/graph-edge-changes-panel").then(mod => mod.GraphEdgeChangesPanel), { ssr: false });

/** Drift lens, relationship changes, evidence lens and reading notes, behind Advanced controls. */
export function GraphOperatorTools({
  drift, driftActive, driftFilter, comparedLabel, driftAttributeSummaries: attributeSummaries, onDriftActive, onDriftFilter,
  showEdgeChanges, edgeChanges, edgeChangesLoading, edgeChangesError,
  evidenceActive, evidenceFilter, evidenceCounts, onEvidenceActive, onEvidenceFilter,
}: {
  /** Null when there is no older snapshot to compare. */
  drift: { counts: Record<ChangeKind, number>; critical: number } | null;
  driftActive: boolean;
  driftFilter: DriftLensFilter;
  comparedLabel: string | undefined;
  driftAttributeSummaries: ReturnType<typeof driftAttributeSummaries>;
  onDriftActive: (active: boolean) => void;
  onDriftFilter: (filter: DriftLensFilter) => void;
  showEdgeChanges: boolean;
  edgeChanges: GraphEdgeChangesResponse | null;
  edgeChangesLoading: boolean;
  edgeChangesError: string | null;
  evidenceActive: boolean;
  evidenceFilter: EvidenceLensFilter;
  evidenceCounts: Record<EvidenceLensFilter, number>;
  onEvidenceActive: (active: boolean) => void;
  onEvidenceFilter: (filter: EvidenceLensFilter) => void;
}) {
  return (
    <section aria-labelledby="graph-operator-tools" className="rounded-xl border border-outline bg-background/70">
      <h3 id="graph-operator-tools" className="px-3 py-2 text-xs font-medium text-ink-secondary">
        Evidence, drift, and operator tools
      </h3>
      <div className="space-y-3 border-t border-outline/80 px-3 py-3">
        {drift && (
          <details className="rounded-2xl border border-outline bg-background/70 p-3">
            <summary className="cursor-pointer list-none text-xs font-medium text-ink-secondary [&::-webkit-details-marker]:hidden">
              Snapshot drift lens · {drift.critical} critical changes
            </summary>
            <div className="mt-3">
              <GraphDriftLegend active={driftActive} onToggleActive={onDriftActive} filter={driftFilter} onFilterChange={onDriftFilter}
                counts={drift.counts} criticalCount={drift.critical} comparedLabel={comparedLabel} attributeSummaries={attributeSummaries} />
            </div>
          </details>
        )}
        {showEdgeChanges && (
          <GraphEdgeChangesPanel changes={edgeChanges} loading={edgeChangesLoading} error={edgeChangesError} comparedLabel={comparedLabel} />
        )}
        <details className="rounded-2xl border border-outline bg-background/70 p-3">
          <summary className="cursor-pointer list-none text-xs font-medium text-ink-secondary [&::-webkit-details-marker]:hidden">
            Evidence lens · {evidenceCounts.all} nodes
          </summary>
          <div className="mt-3">
            <GraphEvidenceLegend active={evidenceActive} onToggleActive={onEvidenceActive} filter={evidenceFilter} onFilterChange={onEvidenceFilter} counts={evidenceCounts} />
          </div>
        </details>
        <details className="group rounded-2xl border border-outline bg-background/70 p-3 text-xs text-ink-secondary">
          <summary className="flex cursor-pointer list-none items-center justify-between [&::-webkit-details-marker]:hidden">
            <span className="font-medium text-foreground">How to read this graph</span>
            <span className="text-xs uppercase tracking-[0.18em] text-ink-tertiary group-open:hidden">show</span>
            <span className="hidden text-xs uppercase tracking-[0.18em] text-ink-tertiary group-open:inline">hide</span>
          </summary>
          <ul className="mt-2 space-y-1.5">
            <li>Snapshot counts cover persisted assets; displayed counts cover this view.</li>
            <li>Select an asset for evidence. Faded assets are outside its context.</li>
            <li>Arrows show recorded direction, not proven access or exploitation.</li>
          </ul>
        </details>
      </div>
    </section>
  );
}
