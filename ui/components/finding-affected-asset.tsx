import { packageVersionLabel } from "@/lib/package-version-label";
import { findingAssetKind } from "@/lib/finding-exposure";
import type { EnrichedVuln } from "@/lib/findings-view";

/** The affected asset named in words; raw graph and record ids stay under technical details. */
export function FindingAffectedAsset({ vuln }: { vuln: EnrichedVuln }) {
  const packageName = vuln.packages.find((name) => name && name !== "asset");
  const multiVersion = Math.max(vuln.package_version_count ?? 0, vuln.package_versions?.length ?? 0) > 1;
  const label = packageName && multiVersion
    ? packageVersionLabel(vuln)
    : packageName
    ? `${packageName}${vuln.current_version && !packageName.includes("@") ? `@${vuln.current_version}` : ""}`
    : vuln.agents[0] || "Affected asset";
  const technicalIds = [
    ["Graph node", vuln.node_id],
    ["Finding node", vuln.finding_node_id],
    ["Finding record", vuln.finding_id],
  ].filter((entry): entry is [string, string] => Boolean(entry[1]));

  return (
    <>
      <p className="mt-2 flex flex-wrap items-baseline gap-2" data-testid="finding-estate-asset">
        <span className="break-all text-sm font-medium text-foreground">{label}</span>
        <span className="text-xs text-ink-tertiary">{findingAssetKind(vuln)}</span>
      </p>
      {technicalIds.length ? (
        <details className="mt-2 text-xs">
          <summary className="cursor-pointer text-ink-tertiary">Technical details</summary>
          <dl className="mt-2 space-y-1">
            {technicalIds.map(([term, value]) => (
              <div key={term} className="flex flex-wrap gap-2">
                <dt className="text-ink-tertiary">{term}</dt>
                <dd className="break-all font-mono text-[11px] text-ink-secondary">{value}</dd>
              </div>
            ))}
          </dl>
        </details>
      ) : null}
    </>
  );
}
