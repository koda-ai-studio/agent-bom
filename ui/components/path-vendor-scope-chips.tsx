"use client";

import { useEffect, useMemo, useState } from "react";

import { VendorMark } from "@/components/vendor-mark";
import { api } from "@/lib/api";
import type { GraphVendorFacets } from "@/lib/api-types";
import { scopeVendors, vendorDisplayName } from "@/lib/path-vendor-scope";

const chipClass = (active: boolean) =>
  `inline-flex min-h-8 sm:min-h-7 items-center gap-1.5 rounded-lg border px-2.5 py-1 text-[11px] font-medium transition ${
    active
      ? "border-sky-600/50 bg-sky-500/10 text-sky-800 dark:text-sky-200"
      : "border-[color:var(--border-subtle)] bg-[color:var(--surface)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
  }`;

const paths = (count: number) => `${count.toLocaleString()} ${count === 1 ? "path" : "paths"}`;

function VendorChip({ vendor, count, prefix, active, onClick }: { vendor: string; count: number; prefix: string; active: boolean; onClick: () => void }) {
  return (
    <li>
      <button type="button" aria-label={`${prefix} ${vendorDisplayName(vendor)} · ${paths(count)}`} aria-pressed={active} onClick={onClick} className={chipClass(active)}>
        <VendorMark vendor={vendor} />
        <span>{vendorDisplayName(vendor)}</span>
        <span className="tabular-nums text-[color:var(--text-tertiary)]">{count.toLocaleString()}</span>
      </button>
    </li>
  );
}

function Label({ children }: { children: React.ReactNode }) {
  return <li aria-hidden className="self-center pr-0.5 text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">{children}</li>;
}

/**
 * Scope the path queue to paths whose source and target nodes sit in
 * different vendors: all of them, from one vendor, or one vendor pair. Counts
 * are paths over the whole snapshot, read server-side, so they never depend on
 * which queue pages loaded; the vendor list scales without hiding pairs.
 */
export function PathVendorScopeChips({ scanId, value, onChange }: {
  scanId: string;
  /** `""` all paths · `any` every cross-vendor path · `source>target` (`*` = any). */
  value: string;
  onChange: (next: string) => void;
}) {
  const [facets, setFacets] = useState<GraphVendorFacets | null>(null);
  const [error, setError] = useState(false);
  const [pickingSource, setPickingSource] = useState(false);
  const [source, target] = scopeVendors(value);

  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;
    setError(false);
    api.getGraphAttackPaths({ scanId, crossVendor: true, limit: 1 })
      .then(response => { if (!cancelled) setFacets(response.vendor_facets ?? null); })
      .catch(() => { if (!cancelled) setError(true); });
    return () => { cancelled = true; };
  }, [scanId]);

  const sources = useMemo(() => {
    const totals = new Map<string, number>();
    for (const pair of facets?.pairs ?? []) totals.set(pair.source_vendor, (totals.get(pair.source_vendor) ?? 0) + pair.paths);
    return [...totals].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  }, [facets]);

  if (error) return <p className="text-xs text-[color:var(--text-tertiary)]">Vendor scope is unavailable for this snapshot.</p>;
  if (!facets) return <div aria-hidden className="h-8 animate-pulse rounded-lg bg-[color:var(--surface-elevated)]" />;
  if (facets.cross_vendor_paths === 0) {
    return <p className="text-xs text-[color:var(--text-tertiary)]">No path in this snapshot starts and ends in different vendors.</p>;
  }
  const targets = source ? facets.pairs.filter(pair => pair.source_vendor === source) : [];
  return (
    <div className="space-y-1.5" data-testid="path-vendor-scope">
      <div role="group" aria-label="Path vendor scope" className="flex flex-wrap items-center gap-1.5">
        <button type="button" aria-pressed={!value} onClick={() => onChange("")} className={chipClass(!value)}>
          All paths · {facets.snapshot_paths.toLocaleString()}
        </button>
        <button type="button" aria-pressed={value === "any"} onClick={() => onChange("any")} className={chipClass(value === "any")}
          title="Paths whose source and target nodes are recorded in different vendors">
          Cross-vendor · {paths(facets.cross_vendor_paths)}
        </button>
      </div>
      <ul aria-label="Source vendor" className="flex flex-wrap gap-1.5">
        <Label>From</Label>
        {sources.filter(([vendor]) => !source || pickingSource || vendor === source).map(([vendor, count]) => (
          <VendorChip key={vendor} vendor={vendor} count={count} prefix="From" active={source === vendor}
            onClick={() => { setPickingSource(false); onChange(source === vendor ? "any" : `${vendor}>*`); }} />
        ))}
        {source && !pickingSource && sources.length > 1 && (
          <li>
            <button type="button" aria-label="Change source vendor" onClick={() => setPickingSource(true)}
              className="min-h-8 px-1 text-[11px] text-[color:var(--text-secondary)] underline underline-offset-4 sm:min-h-7">Change</button>
          </li>
        )}
      </ul>
      {targets.length > 0 && (
        <ul aria-label="Target vendor" className="flex flex-wrap gap-1.5">
          <Label>To</Label>
          {targets.map(pair => (
            <VendorChip key={pair.target_vendor} vendor={pair.target_vendor} count={pair.paths} prefix="To" active={target === pair.target_vendor}
              onClick={() => onChange(target === pair.target_vendor ? `${source}>*` : `${source}>${pair.target_vendor}`)} />
          ))}
        </ul>
      )}
    </div>
  );
}
