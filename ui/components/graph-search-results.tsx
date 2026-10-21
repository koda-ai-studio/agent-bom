"use client";

import { VendorMark } from "@/components/vendor-mark";
import { assetKindLabel } from "@/lib/asset-icon-registry";
import type { UnifiedNode } from "@/lib/graph-schema";
import { nodeRiskAssessment, nodeRiskLabel } from "@/lib/node-risk-assessment";
import { vendorDisplayName } from "@/lib/path-vendor-scope";
import { nodeVendorAccount } from "@/lib/node-vendor";

/**
 * Graph search hits. Same-named assets are common across vendors (a Snowflake
 * stage and the S3 bucket it reads), so every hit names its vendor mark,
 * account or project and kind; the full node id is the tooltip.
 */
export function GraphSearchResults({ results, severity, onSelect }: {
  results: UnifiedNode[];
  severity: string | null | undefined;
  onSelect: (node: UnifiedNode) => void;
}) {
  if (results.length === 0) return null;
  return (
    <div className="mt-2 rounded-2xl border border-outline bg-background/90 p-2">
      <div className="mb-2 px-1 text-[0.625rem] uppercase tracking-[0.18em] text-ink-tertiary">
        Search respects current entity scope{severity ? ` and ${severity}+ severity` : ""}
      </div>
      <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">
        {results.map((result) => {
          const { vendor, account } = nodeVendorAccount(result);
          const kind = assetKindLabel({ entityType: String(result.entity_type), attributes: result.attributes, provider: vendor || null });
          const assessed = nodeRiskAssessment(result.risk_assessment).status === "assessed";
          return (
            <button key={result.id} type="button" title={result.id} data-testid={`graph-search-result-${result.id}`}
              onClick={() => onSelect(result)} className="graph-page-result min-w-0 text-left">
              <p className="flex min-w-0 items-center gap-1.5 text-sm font-medium text-foreground">
                {vendor && <VendorMark vendor={vendor} />}
                <span className="truncate">{result.label}</span>
              </p>
              <p className="mt-1 flex min-w-0 flex-wrap items-center gap-x-1.5 text-[0.6875rem] text-ink-secondary">
                <span className="font-medium">{kind}</span>
                {vendor && <span aria-hidden>·</span>}
                {vendor && <span className="truncate">{vendorDisplayName(vendor)}{account ? ` · ${account}` : ""}</span>}
              </p>
              {(result.severity || assessed) && (
                <div className="mt-1.5 flex flex-wrap gap-2 text-[0.625rem] text-ink-tertiary">
                  {result.severity && <span>{result.severity}</span>}
                  {assessed && <span>risk {nodeRiskLabel(result.risk_score, result.risk_assessment)}</span>}
                </div>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}
