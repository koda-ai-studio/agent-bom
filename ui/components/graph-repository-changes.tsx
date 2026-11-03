"use client";

import Link from "next/link";
import type { GraphRepositoryChangeSummary } from "@/lib/api-contracts/graph-views";
import { changedNodeHref } from "@/lib/graph-estate-changes";

const labels: Record<string,string> = {workspace_packages:"Workspace packages",dbt_models:"dbt models",pipelines:"Pipelines"};

/** Source annotations stay in the details drawer; they never imply execution or remediation. */
export function GraphRepositoryChanges({change,onOpenDiff}:{change?:GraphRepositoryChangeSummary|undefined;onOpenDiff:()=>void}) {
  if (!change) return null;
  if (change.status === "unavailable") return <p className="text-xs text-ink-tertiary">Repository comparison unavailable: {change.reason?.replaceAll("_"," ") ?? "basis not recorded"}.</p>;
  return <details className="rounded-lg border border-outline px-2 py-1.5 text-xs">
    <summary className="cursor-pointer font-medium text-foreground">Repository changes</summary>
    <div className="mt-2 space-y-2">
      {change.ref && <p className="break-all text-ink-tertiary">{change.ref}</p>}
      <div className="flex flex-wrap gap-x-3 gap-y-1 text-ink-secondary">{Object.entries(change.counts ?? {}).map(([key,count]) =>
        <span key={key} className="tabular-nums">{labels[key] ?? key} +{count.added} −{count.removed}</span>)}</div>
      <ul className="space-y-1">{(change.rows ?? []).slice(0,10).map(row => <li key={`${row.change}:${row.id}`} className="flex items-start justify-between gap-2">
        <span className="min-w-0 break-words text-ink-secondary">{row.label} · {row.change === "removed" ? "no longer recorded" : "newly recorded"}</span>
        <Link className="shrink-0 underline underline-offset-4" href={changedNodeHref(row.id,row.label,row.scan_id)} aria-label={`Open ${row.label} in its recorded snapshot`}>Open</Link>
      </li>)}</ul>
      {change.files_with_new_findings && <p className="text-ink-secondary">Files with new finding links: {change.files_with_new_findings.count}{change.files_with_new_findings.status === "partial" ? "+ (bounded sample)" : ""}</p>}
      {change.status === "partial" && <p className="text-amber-700 dark:text-amber-300">Some detail is outside this bounded comparison window.</p>}
      <p className="text-ink-tertiary">No longer recorded does not establish remediation. Static declarations do not establish execution.</p>
      <button type="button" onClick={onOpenDiff} className="underline underline-offset-4">Open full repository diff</button>
    </div>
  </details>;
}
