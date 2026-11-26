"use client";

import { formatGraphFindingCounts, formatGraphHeadline } from "@/lib/graph-headline";
import { readAttackPathCounts } from "@/lib/graph-snapshot-metrics";
import type { GraphPageModel } from "@/components/graph-page-view";

export function GraphHeadlineMetrics({ page, supportingFolded = false, compact = false, details = false }: { page: GraphPageModel; supportingFolded?: boolean; compact?: boolean; details?: boolean }) {
  const { investigationMode, selectedAttackPath, firstFramePending, flow, connectionPreview, previewExpanded } = page;
  const pathCounts = readAttackPathCounts(page.graphData?.stats.attack_paths);
  return <>
      {!investigationMode && !selectedAttackPath && !firstFramePending && flow.summary && (
        <div
          data-testid={details ? "graph-headline-details" : "graph-headline-metrics"}
          className="text-xs text-ink-secondary"
        >
          {compact ? formatGraphFindingCounts(flow.summary, "loaded scope") : formatGraphHeadline(flow.summary, pathCounts?.retained_count ?? null, (supportingFolded || connectionPreview && !previewExpanded) ? "loaded scope" : "view")}
          {!compact && pathCounts && <span title={pathCounts.basis}> · {pathCounts.assessed_count.toLocaleString()} assessed</span>}
          {!compact && flow.summary.costUsd30d > 0 && (
            <>
              {" · "}
              <span className="font-mono text-foreground">
                {flow.summary.costUsd30d.toLocaleString(undefined, {
                  style: "currency",
                  currency: "USD",
                  maximumFractionDigits:
                    flow.summary.costUsd30d < 100 ? 2 : 0,
                })}
              </span>{" "}
              spend 30d
            </>
          )}
          {!compact && flow.summary.expensiveExposed > 0 && (
            <>
              {" · "}
              <span className="font-mono text-red-700 dark:text-red-200">
                {flow.summary.expensiveExposed.toLocaleString()}
              </span>{" "}
              expensive & exposed
            </>
          )}
        </div>
      )}
  </>;
}
