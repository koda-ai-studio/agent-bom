"use client";

import { Layers, Loader2 } from "lucide-react";

import type { GraphRollupResponse } from "@/lib/api-types";
import type { ScopeCrumb } from "@/lib/graph-scope-crumbs";

type RollupBreadcrumb = ScopeCrumb;

/** Scope-navigation status above the roll-up canvas: level counts, estate issue basis, breadcrumb. */
export function RollupNavigationPanel({
  summary,
  estateNodeCount,
  estateIssues,
  breadcrumbs,
  loading,
  error,
  unavailable,
  active,
  decisionAvailable,
  decisionActive,
  onDismiss,
  onReset,
  onBreadcrumb,
  onDecisionMode,
  onRetry,
}: {
  summary: GraphRollupResponse | null;
  estateNodeCount: number;
  estateIssues: string | null;
  breadcrumbs: RollupBreadcrumb[];
  loading: boolean;
  error: string | null;
  unavailable: boolean;
  active: boolean;
  decisionAvailable: boolean;
  decisionActive: boolean;
  onDismiss: () => void;
  onReset: () => void;
  onBreadcrumb: (index: number) => void;
  onDecisionMode: () => void;
  onRetry: () => void;
}) {
  const visibleCount =
    summary?.mode === "drilldown"
      ? (summary.children?.length ?? 0)
      : (summary?.top_level?.length ?? 0);

  return (
    <div className="mt-3 rounded-2xl border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-900 dark:text-emerald-100">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-2">
          <Layers className="mt-0.5 h-4 w-4 text-emerald-700 dark:text-emerald-300" />
          <div>
            <p className="text-[10px] uppercase tracking-[0.24em] text-emerald-700 dark:text-emerald-300">
              Scope navigation
            </p>
            <p className="mt-1 text-sm font-medium text-emerald-950 dark:text-emerald-50">
              {active
                ? `${visibleCount.toLocaleString()} nodes and scopes at this level · ${estateNodeCount.toLocaleString()} nodes in snapshot${estateIssues ? ` · ${estateIssues}` : ""}`
                : error
                  ? "Could not load this scope"
                : unavailable
                  ? `Roll-up unavailable · ${estateNodeCount} nodes in snapshot`
                : `Loading CONTAINS roll-up · ${estateNodeCount} nodes in snapshot`}
            </p>
            {/* The rule is stated once, inline. It was a third line of prose on
                every render, above a canvas that had no room to spare. */}
            {error && (
              <p className="mt-1 text-[11px] text-amber-800 dark:text-amber-200">{error}</p>
            )}
            {unavailable && (
              <p className="mt-1 text-[11px] text-emerald-800 dark:text-emerald-200/80">
                No containment scope is available; showing the real topology.
              </p>
            )}
            {loading && (
              <p className="mt-1 flex items-center gap-1 text-[11px] text-emerald-800 dark:text-emerald-200">
                <Loader2 className="h-3 w-3 animate-spin" />
                Collapsing containment hierarchy
              </p>
            )}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {error ? <button type="button" onClick={onRetry} className="graph-chip-emerald">Retry scope</button> : null}
          {decisionAvailable && !decisionActive ? (
            <button type="button" onClick={onDecisionMode} className="graph-chip-emerald">
              Risk rollup
            </button>
          ) : null}
          <button
            type="button"
            onClick={onDismiss}
            className="graph-chip-emerald"
          >
            Open node view
          </button>
        </div>
      </div>

      {breadcrumbs.length > 0 && (
        <nav
          aria-label="Roll-up breadcrumb"
          className="mt-3 flex flex-wrap items-center gap-1 text-[11px] text-emerald-900 dark:text-emerald-100"
        >
          <button
            type="button"
            onClick={onReset}
            className="rounded border border-emerald-500/30 bg-emerald-50 px-2 py-0.5 text-emerald-900 transition hover:border-emerald-500 dark:bg-emerald-950/50 dark:text-emerald-100"
          >
            Estate root
          </button>
          {breadcrumbs.map((crumb, index) => (
            <span key={crumb.id} className="flex items-center gap-1">
              <span className="text-emerald-400/70">/</span>
              <button
                type="button"
                onClick={() => onBreadcrumb(index)}
                className="graph-chip-emerald-truncate"
              >
                {crumb.label}
              </button>
            </span>
          ))}
        </nav>
      )}
    </div>
  );
}

