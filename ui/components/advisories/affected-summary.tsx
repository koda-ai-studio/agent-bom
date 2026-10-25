import { AlertTriangle } from "lucide-react";

import { SeverityBadge } from "@/components/severity-badge";
import { StatCard } from "@/components/stat-card";
import type { AdvisoryAffectedResponse } from "@/lib/advisory-affected";

import { formatUtc } from "./advisory-format";

const plural = (count: number, noun: string) => `${count.toLocaleString()} ${noun}${count === 1 ? "" : "s"}`;

export function AdvisoryHeader({ advisory }: { advisory: AdvisoryAffectedResponse["advisory"] }) {
  return (
    <div className="min-w-0 space-y-1.5">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="font-mono text-base font-semibold text-foreground">{advisory.id}</h2>
        <SeverityBadge severity={advisory.severity} />
        <span data-testid="advisory-source" className="rounded-full border border-outline bg-surface-muted px-2 py-0.5 text-[11px] font-medium text-ink-secondary">
          {advisory.source === "operator_advisory" ? "Operator advisory" : "Feed advisory"}
        </span>
        {advisory.aliases.length ? <span className="text-xs text-ink-tertiary">Also {advisory.aliases.join(", ")}</span> : null}
      </div>
      <p className="max-w-3xl text-sm text-ink-secondary">{advisory.summary}</p>
      <p className="text-xs text-ink-tertiary">
        {advisory.fixed_versions.length ? `Fixed in ${advisory.fixed_versions.join(", ")}` : "No fixed version published"}
        {advisory.published_at ? ` · Published ${formatUtc(advisory.published_at)}` : ""}
      </p>
    </div>
  );
}

/** Verdict tiles straight from `summary`; never recomputed from the visible page. */
export function AffectedSummaryTiles({ answer }: { answer: AdvisoryAffectedResponse }) {
  const { summary } = answer;
  return (
    <div className="space-y-2">
      <ul aria-label="Verdict summary" className="grid grid-cols-2 gap-2 lg:grid-cols-4">
        <li><StatCard label="Affected" value={summary.affected} accent="critical" /></li>
        <li><StatCard label="Possibly affected (distro)" value={summary.possibly_affected} accent="medium" /></li>
        <li><StatCard label="Not affected" value={summary.not_affected} /></li>
        <li><StatCard label="Clean scanned" value={summary.clean_scanned} /></li>
      </ul>
      <p className="text-xs text-ink-tertiary">{plural(summary.assets_examined, "asset")} · {plural(summary.reports_examined, "scan report")} examined</p>
    </div>
  );
}

/** Honesty notes: incomplete answers, warnings, and zero-affected wording that never claims more than was scanned. */
export function AffectedNotices({ answer }: { answer: AdvisoryAffectedResponse }) {
  const { summary } = answer;
  const nothingScanned = summary.reports_examined === 0;
  return (
    <>
      {!answer.complete ? (
        <div role="status" className="flex items-start gap-2 rounded-xl border border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] p-3 text-sm">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[color:var(--status-warn)]" aria-hidden />
          <div className="min-w-0">
            <p className="font-medium text-foreground">Incomplete — some packages could not be decided</p>
            <p className="mt-0.5 text-xs text-ink-secondary">
              {nothingScanned ? "No scan reports were available to match." : "Counts cover only the packages that could be decided. Re-check after the next scan or feed sync."}
            </p>
          </div>
        </div>
      ) : null}
      {answer.warnings.length ? (
        <ul aria-label="Warnings" className="space-y-1 text-xs text-ink-secondary">
          {answer.warnings.map(warning => <li key={warning} className="flex gap-2"><AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[color:var(--status-warn)]" aria-hidden />{warning}</li>)}
        </ul>
      ) : null}
      {summary.affected === 0 ? (
        <p className="rounded-xl border border-outline bg-surface-muted px-3 py-2 text-sm text-ink-secondary">
          {nothingScanned
            ? "Nothing has been scanned yet, so no asset can be matched to this advisory."
            : `Not found in what was scanned: no confirmed match in ${plural(summary.assets_examined, "asset")} across ${plural(summary.reports_examined, "scan report")}. Assets that were never scanned are not covered.`}
        </p>
      ) : null}
    </>
  );
}
