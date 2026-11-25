"use client";

import { formatGraphHeadline } from "@/lib/graph-headline";
import { readAttackPathCounts } from "@/lib/graph-snapshot-metrics";
import type { GraphPageModel } from "@/components/graph-page-view";

export function GraphHeadlineMetrics({ page, supportingFolded = false }: { page: GraphPageModel; supportingFolded?: boolean }) {
  const { investigationMode, selectedAttackPath, firstFramePending, flow, connectionPreview, previewExpanded } = page;
  const pathCounts = readAttackPathCounts(page.graphData?.stats.attack_paths);
  return <>
      {!investigationMode && !selectedAttackPath && !firstFramePending && flow.summary && (
        <div
          data-testid="graph-headline-metrics"
          className="text-xs text-ink-secondary"
        >
          {formatGraphHeadline(flow.summary, pathCounts?.retained_count ?? null, (supportingFolded || connectionPreview && !previewExpanded) ? "loaded scope" : "view")}
          {pathCounts && <span title={pathCounts.basis}> · {pathCounts.assessed_count.toLocaleString()} assessed</span>}
          {flow.summary.costUsd30d > 0 && (
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
          {flow.summary.expensiveExposed > 0 && (
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
