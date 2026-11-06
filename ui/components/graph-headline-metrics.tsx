"use client";

import { formatGraphHeadline } from "@/lib/graph-headline";
import type { GraphPageModel } from "@/components/graph-page-view";

export function GraphHeadlineMetrics({ page }: { page: GraphPageModel }) {
  const { investigationMode, selectedAttackPath, firstFramePending, flow, snapshotAttackPathCount, connectionPreview, previewExpanded } = page;
  return <>
      {!investigationMode && !selectedAttackPath && !firstFramePending && flow.summary && (
        <div
          data-testid="graph-headline-metrics"
          className="text-xs text-ink-secondary"
        >
          {formatGraphHeadline(flow.summary, snapshotAttackPathCount, connectionPreview && !previewExpanded ? "loaded scope" : "view")}
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
