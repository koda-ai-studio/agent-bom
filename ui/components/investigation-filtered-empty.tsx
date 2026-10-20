import type { ReactNode } from "react";

import { GraphPresetControls, type InvestigationPresetFilters } from "@/components/graph-preset-controls";
import { GraphEmptyState } from "@/components/graph-state-panels";
import { InvestigationFilterChips } from "@/components/investigation-filter-chips";
import { InvestigationFilterDrawer } from "@/components/investigation-path-workspace";

/** Paths exist but the investigation filters exclude every loaded one. */
export function InvestigationFilteredEmpty({ filters, onFiltersChange, onClear, environments, morePages, continuation }: {
  filters: InvestigationPresetFilters;
  onFiltersChange: (next: InvestigationPresetFilters) => void;
  onClear: () => void;
  environments: string[];
  morePages: boolean;
  continuation: ReactNode;
}) {
  return (
    <section className="space-y-4 rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
      <InvestigationFilterDrawer>
        <InvestigationFilterChips filters={filters} onChange={onFiltersChange} environments={environments} />
        <GraphPresetControls filters={filters} onApply={onFiltersChange} />
      </InvestigationFilterDrawer>
      <GraphEmptyState
        title={morePages ? "No matching paths in loaded pages" : "No paths match the current investigation filters"}
        detail={morePages ? "Continue through the queue with these filters. Matches outside loaded pages are unknown." : "No loaded paths match. Clear severity, layer, evidence, or environment chips to widen the queue."}
        suggestions={[
          "Clear one filter chip at a time to widen the queue.",
          "Load a saved preset that matches this estate.",
          "Open the full graph for topology outside the filtered set.",
        ]}
      />
      <button type="button" onClick={onClear}
        className="rounded-lg border border-[color:var(--border-subtle)] px-3 py-1.5 text-xs text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]">
        Clear investigation filters
      </button>
      {continuation}
    </section>
  );
}
