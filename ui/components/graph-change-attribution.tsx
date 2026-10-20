"use client";

import { VendorMark } from "@/components/vendor-mark";
import type { GraphChangeAttribution as Attribution } from "@/lib/api-types";
import { vendorDisplayName } from "@/lib/path-vendor-scope";

const n = (value: number) => value.toLocaleString();

function delta(counts: { added: number; removed: number; changed: number }): string {
  const parts = [counts.added ? `+${n(counts.added)}` : "", counts.removed ? `−${n(counts.removed)}` : ""].filter(Boolean).join(" ");
  return [parts, counts.changed ? `${n(counts.changed)} changed` : ""].filter(Boolean).join(" · ") + " nodes";
}

/** Which connector produced the changes: changed nodes per recorded vendor and account, not the scan's request label. */
export function GraphChangeAttribution({ attribution }: { attribution: Attribution | undefined }) {
  if (!attribution || (attribution.sources.length === 0 && !attribution.unattributed.added && !attribution.unattributed.removed)) return null;
  const bare = attribution.unattributed.added + attribution.unattributed.removed + attribution.unattributed.changed;
  return (
    <div className="space-y-1">
      <p className="text-[11px] font-medium text-ink-tertiary">Collected from</p>
      <ul aria-label="Changed nodes by collected source" className="flex flex-wrap gap-1.5">
        {attribution.sources.map(source => (
          <li key={`${source.vendor}:${source.account}`} title={`${vendorDisplayName(source.vendor)} ${source.account}`.trim()}
            className="inline-flex min-w-0 max-w-full items-center gap-1.5 rounded-md border border-outline bg-surface px-2 py-0.5 text-[11px] text-ink-secondary">
            <VendorMark vendor={source.vendor} className="h-3.5 w-3.5" />
            <span className="truncate text-foreground">{vendorDisplayName(source.vendor)}{source.account ? ` · ${source.account}` : ""}</span>
            <span className="shrink-0 font-mono tabular-nums">{delta(source)}</span>
          </li>
        ))}
      </ul>
      {(attribution.omitted_sources > 0 || bare > 0) && (
        <p className="text-[11px] text-ink-tertiary">
          {attribution.omitted_sources > 0 && `${n(attribution.omitted_sources)} more sources not shown. `}
          {bare > 0 && `${n(bare)} nodes without a recorded vendor.`}
        </p>
      )}
    </div>
  );
}
