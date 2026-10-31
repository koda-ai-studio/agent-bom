import type { AdvisoryAffectedRow } from "@/lib/advisory-affected";

import { formatUtc } from "./advisory-format";
import { AffectedAssetCards } from "./affected-asset-cards";
import { AffectedAssetIdentity } from "./affected-asset-identity";
import { BlastRadiusLink, PatchTarget, VerdictBadge, VerdictDetail, provenanceLabel, rowKey } from "./affected-row-parts";

const th = "px-3 py-2 font-medium";

/**
 * One row per asset × package. A fixed-layout table that never exceeds its container (wide screens),
 * stacked cards below ``lg`` where the content column cannot hold the answer columns side by side.
 */
export function AffectedAssetsTable({ rows }: { rows: AdvisoryAffectedRow[] }) {
  return (
    <div data-testid="affected-assets" className="min-w-0">
      <AffectedAssetCards rows={rows} />
      <div className="hidden rounded-xl border border-outline lg:block">
        <table aria-label="Affected assets" className="w-full table-fixed text-left text-sm">
          <colgroup>
            <col className="w-[24%]" />
            <col className="w-[18%]" />
            <col className="w-[14%]" />
            <col className="w-[26%]" />
            <col className="w-[18%]" />
          </colgroup>
          <thead className="bg-surface-muted text-xs text-ink-tertiary">
            <tr>
              <th scope="col" className={th}>Asset</th>
              <th scope="col" className={th}>Package · installed</th>
              <th scope="col" className={th}>Patch target</th>
              <th scope="col" className={th}>Verdict</th>
              <th scope="col" className={th}>Evidence</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-outline">
            {rows.map(row => (
              <tr key={rowKey(row)} className="align-top">
                <td className="px-3 py-2">
                  <AffectedAssetIdentity row={row} />
                  <div className="mt-1.5"><BlastRadiusLink row={row} /></div>
                </td>
                <td className="px-3 py-2">
                  <p className="truncate font-mono text-xs text-foreground" title={row.package.purl ?? row.package.cpe}>{row.package.name}</p>
                  <p className="break-all font-mono text-xs text-ink-secondary">{row.installed_version}</p>
                  <p className="text-xs text-ink-tertiary">{row.package.ecosystem}</p>
                </td>
                <td className="px-3 py-2"><PatchTarget row={row} /></td>
                <td className="px-3 py-2">
                  <VerdictBadge row={row} />
                  <VerdictDetail row={row} />
                </td>
                <td className="px-3 py-2 text-xs text-ink-secondary">
                  <p>{provenanceLabel(row)}</p>
                  <p className="text-ink-tertiary">{formatUtc(row.last_observed_at)}</p>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
