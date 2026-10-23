"use client";

import { VendorMark } from "@/components/vendor-mark";
import type { GraphChangeAttribution as Attribution, GraphEstateChangeSource } from "@/lib/api-types";
import { vendorDisplayName } from "@/lib/path-vendor-scope";

const n = (value: number) => value.toLocaleString();

function delta(counts: { added: number; removed: number; changed: number }): string {
  const parts = [counts.added ? `+${n(counts.added)}` : "", counts.removed ? `−${n(counts.removed)}` : ""].filter(Boolean).join(" ");
  return [parts, counts.changed ? `${n(counts.changed)} changed` : ""].filter(Boolean).join(" · ") + " nodes";
}

const HEADING_VENDORS = 3;

/** A source's title: its named target, or for an unnamed scan request, the vendors its changes were collected from. */
export function changeSourceHeading(source: Pick<GraphEstateChangeSource, "label" | "label_basis" | "changes_by_source">): string {
  const vendors = [...new Set((source.changes_by_source?.sources ?? []).map((row) => vendorDisplayName(row.vendor)))];
  if (source.label_basis !== "default_scan_request" || vendors.length === 0) return source.label;
  const more = vendors.length - HEADING_VENDORS;
  const unlisted = source.changes_by_source?.omitted_sources ? " and unlisted sources" : "";
  return vendors.slice(0, HEADING_VENDORS).join(", ") + (more > 0 ? ` +${more} more` : "") + unlisted;
}

/** Which connector produced the changes: changed nodes per recorded vendor and account, not the scan's request label. */
export function GraphChangeAttribution({ attribution }: { attribution: Attribution | undefined }) {
  if (!attribution || (attribution.sources.length === 0 && !attribution.unattributed.added && !attribution.unattributed.removed)) return null;
  const bare = attribution.unattributed.added + attribution.unattributed.removed + attribution.unattributed.changed;
  return (
    <div className="space-y-1">
      <p className="text-[0.6875rem] font-medium text-ink-tertiary">Collected from</p>
      <ul aria-label="Changed nodes by collected source" className="flex flex-wrap gap-1.5">
        {attribution.sources.map(source => (
          <li key={`${source.vendor}:${source.account}`} title={`${vendorDisplayName(source.vendor)} ${source.account}`.trim()}
            className="inline-flex min-w-0 max-w-full items-center gap-1.5 rounded-md border border-outline bg-surface px-2 py-0.5 text-[0.6875rem] text-ink-secondary">
            <VendorMark vendor={source.vendor} className="h-3.5 w-3.5" />
            <span className="truncate text-foreground">{vendorDisplayName(source.vendor)}{source.account ? ` · ${source.account}` : ""}</span>
            <span className="shrink-0 font-mono tabular-nums">{delta(source)}</span>
          </li>
        ))}
      </ul>
      {(attribution.omitted_sources > 0 || bare > 0) && (
        <p className="text-[0.6875rem] text-ink-tertiary">
          {attribution.omitted_sources > 0 && `${n(attribution.omitted_sources)} more sources not shown. `}
          {bare > 0 && `${n(bare)} nodes without a recorded vendor.`}
        </p>
      )}
    </div>
  );
}
