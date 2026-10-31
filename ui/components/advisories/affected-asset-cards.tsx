import type { AdvisoryAffectedRow } from "@/lib/advisory-affected";

import { formatUtc } from "./advisory-format";
import { AffectedAssetIdentity } from "./affected-asset-identity";
import { BlastRadiusLink, PatchTarget, VerdictBadge, VerdictDetail, provenanceLabel, rowKey } from "./affected-row-parts";

/** Narrow screens: one stacked card per asset, the verdict and patch target always on screen. */
export function AffectedAssetCards({ rows }: { rows: AdvisoryAffectedRow[] }) {
  return (
    <ul aria-label="Affected assets" className="space-y-2 lg:hidden">
      {rows.map(row => (
        <li key={rowKey(row)} data-testid="affected-asset-card" className="min-w-0 space-y-2 rounded-xl border border-outline bg-surface px-3 py-2.5">
          <AffectedAssetIdentity row={row} />
          <div className="min-w-0">
            <VerdictBadge row={row} />
            <VerdictDetail row={row} />
          </div>
          <p className="flex min-w-0 flex-wrap items-baseline gap-x-1.5 text-xs">
            <span className="break-all font-mono text-foreground">{row.package.name} {row.installed_version}</span>
            <span aria-hidden className="text-ink-tertiary">→</span>
            <span className="sr-only">patch target</span>
            <PatchTarget row={row} />
          </p>
          <p className="text-xs text-ink-tertiary">{provenanceLabel(row)} · last observed {formatUtc(row.last_observed_at)}</p>
          <BlastRadiusLink row={row} />
        </li>
      ))}
    </ul>
  );
}
