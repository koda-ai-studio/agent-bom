"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { buildFindingReturnHref } from "@/lib/finding-investigation-href";

/** Navigation provenance is not a claim that this graph proves the finding. */
export function FindingInvestigationContext({ compact = false }: { compact?: boolean }) {
  const params = useSearchParams();
  const href = buildFindingReturnHref(params);
  if (!href) return null;
  const finding = params.get("finding") || params.get("related_finding");
  const advisory = params.get("cve");
  const sourceScan = params.get("finding_scan") || params.get("scan");
  const changedSnapshot = sourceScan && params.get("scan") && sourceScan !== params.get("scan");
  if (compact) {
    return (
      <aside aria-label="Finding investigation context" className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-ink-secondary"
        title="Graph relationships require their own evidence; this link preserves your finding selection.">
        <span className="font-medium text-foreground">Finding {advisory ?? finding}</span>
        <span className="min-w-0 truncate">{advisory ? `Record ${finding}` : null}{advisory && sourceScan ? " · " : null}{sourceScan ? `Source snapshot: ${sourceScan}` : null}</span>
        {changedSnapshot ? <span role="note">Viewing a different graph snapshot.</span> : null}
        <Link href={href} className="font-medium text-emerald-800 hover:underline dark:text-emerald-300">Return to finding</Link>
      </aside>
    );
  }
  return (
    <aside aria-label="Finding investigation context" className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-outline bg-surface p-3 text-sm">
      <div className="min-w-0 space-y-1">
        {advisory ? (
          <p className="font-medium">Finding {advisory}</p>
        ) : (
          <p className="font-medium">Finding context <code className="break-all text-xs">{finding}</code></p>
        )}
        <p className="break-all text-xs text-ink-tertiary">
          {advisory ? `Record ${finding}` : null}
          {advisory && sourceScan ? " · " : null}
          {sourceScan ? `Source snapshot: ${sourceScan}` : null}
        </p>
        <p className="text-xs text-ink-secondary">Graph relationships require their own evidence; this link preserves your finding selection.</p>
        {changedSnapshot && <p role="note" className="text-xs text-ink-secondary">Viewing a different graph snapshot. Return opens the original finding snapshot.</p>}
      </div>
      <Link href={href} className="shrink-0 rounded-lg border border-outline px-3 py-2 text-emerald-800 dark:text-emerald-300">Return to finding</Link>
    </aside>
  );
}
