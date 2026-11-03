"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { get } from "@/lib/api-transport";

export const CONTEXT_LABELS: Record<string, string> = {
  test: "Tests and fixtures", example: "Examples", documentation: "Documentation", unclassified: "Unclassified",
};
export type ContextSummary = {
  contexts: { context: string; total: number; severity: Record<string, number> }[];
  count: number; approximate: boolean; warnings: string[];
};

export function FindingContextFilter({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  return <label className="flex items-center gap-2 text-xs text-ink-secondary">Path context
    <select aria-label="Path context" value={value} onChange={(event) => onChange(event.target.value)} className="rounded-lg border border-outline bg-surface px-2 py-1.5 text-foreground">
      <option value="">All contexts</option>
      {Object.entries(CONTEXT_LABELS).map(([key, label]) => <option key={key} value={key}>{label}</option>)}
    </select>
  </label>;
}

export function FindingContextPanel() {
  const [data, setData] = useState<ContextSummary | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    get<ContextSummary>("/v1/findings/context-summary", { signal: controller.signal })
      .then(setData).catch(() => { if (!controller.signal.aborted) setUnavailable(true); });
    return () => controller.abort();
  }, []);
  if (!data) return unavailable ? <p className="text-xs text-ink-secondary">Path context unavailable. Headline posture includes all contexts.</p> : null;
  if (!data.contexts?.some((row) => row.context !== "unclassified" && row.total > 0)) return null;
  return <section aria-label="Finding path context" className="rounded-xl border border-outline bg-surface p-4">
    <h2 className="text-sm font-semibold">Interpret posture by path context</h2>
    <p className="mt-1 text-xs text-ink-secondary">Headline scores include all contexts. These are open finding occurrences in the configured window; issue counts may differ.</p>
    <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      {data.contexts.map((row) => <Link key={row.context} href={`/findings?lane=all&path_context=${encodeURIComponent(row.context)}`} className="rounded-lg border border-outline p-3 hover:bg-surface-elevated">
        <span className="text-xs text-ink-secondary">{CONTEXT_LABELS[row.context] ?? row.context}</span>
        <span className="mt-1 block text-lg font-semibold">{data.approximate ? "At least " : ""}{row.total.toLocaleString()}</span>
        <span className="text-xs text-ink-secondary">{row.severity.critical ?? 0} critical · {row.severity.high ?? 0} high</span>
      </Link>)}
    </div>
    <p className="mt-3 text-xs text-ink-secondary">Path names are a review hint, not proof of deployment or a false positive. Unclassified includes missing context. Severity and compliance evidence are retained in every view.</p>
    {data.approximate && <p role="status" className="mt-2 text-xs text-amber-800 dark:text-amber-300">Context coverage is partial; counts are lower bounds.</p>}
  </section>;
}
