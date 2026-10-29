"use client";
import { severityColor } from "@/lib/api";
import { vulnRowKey, type EnrichedVuln } from "@/lib/findings-view";
import type { FindingLane } from "@/lib/finding-lanes";
const CLOUD_CHECK_RESULTS: Record<string, string> = {
  CIS_FAIL: "Failed",
  CIS_ERROR: "Not evaluated",
  CLOUD_BEST_PRACTICE_FAIL: "Failed",
  CLOUD_BEST_PRACTICE_ERROR: "Not evaluated",
};

export interface LaneEvidence {
  resource?: string | undefined; account?: string | undefined; provider?: string | undefined; environment?: string | undefined;
  rule?: string | undefined; line?: number | undefined; expected?: string | undefined; observed?: string | undefined; remediation?: string | undefined;
}
export type LaneFinding = EnrichedVuln & { lane_evidence?: LaneEvidence };
export function FindingLaneTable({ lane, findings, onSelect }: { lane: FindingLane; findings: LaneFinding[]; onSelect: (id: string) => void }) {
  const keyLabel = lane === "iac" ? "File / rule" : lane === "identity" ? "Principal / scope" : lane === "cloud" ? "Resource / scope" : "Affected resource";
  return <div className="overflow-hidden rounded-xl border border-outline bg-background">
    <div className="hidden grid-cols-[minmax(0,2fr)_minmax(0,1.5fr)_minmax(0,2fr)_7rem] gap-4 border-b border-outline bg-surface px-4 py-3 text-xs font-medium uppercase text-ink-tertiary lg:grid" aria-hidden="true">
      <span>{lane === "cloud" ? "Control / result / severity" : "Finding / severity"}</span><span>{keyLabel}</span><span>Evidence / remediation</span><span>Action</span>
    </div>
    <ul aria-label={`${lane} findings`} className="divide-y divide-outline">
      {findings.map((finding) => {
        const evidence = finding.lane_evidence ?? {};
        const count = finding.occurrence_count ?? 1;
        const checkResult = lane === "cloud" ? CLOUD_CHECK_RESULTS[finding.finding_type ?? ""] ?? "Unreported" : null;
        return <li key={vulnRowKey(finding)} className="grid gap-3 p-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,1.5fr)_minmax(0,2fr)_7rem] lg:gap-4">
          <div className="min-w-0 space-y-2">
            <p className="break-words text-sm font-medium text-foreground">{finding.summary || finding.id}</p>
            <p className="flex flex-wrap items-center gap-1.5 text-xs">{checkResult && <span aria-label={`Check result: ${checkResult}`} className="rounded border border-outline px-1.5 py-0.5 font-medium text-foreground">{checkResult}</span>}<span className={`rounded border px-1.5 py-0.5 capitalize ${severityColor(finding.severity)}`}>{finding.severity === "none" ? "Unrated" : finding.severity}</span><span className="text-ink-tertiary">{finding.severity_source === "benchmark-mapped" ? "Benchmark mapping" : finding.severity_source || "Source unreported"}</span></p>
            {count > 1 && <details className="text-xs text-ink-secondary"><summary className="cursor-pointer">{count} resource findings</summary><ul className="mt-2 space-y-1">{(finding.occurrences ?? []).map((occurrence, i) => <li className="break-words" key={occurrence.finding_id ?? i}>{occurrence.asset?.name || "Resource identity withheld"}</li>)}</ul>{finding.occurrences_truncated && <p>Showing a bounded resource sample.</p>}</details>}
          </div>
          <div className="min-w-0 space-y-1 text-xs text-ink-secondary">
            {count > 1 && <p className="text-ink-tertiary">Representative resource</p>}
            <p className="break-words font-mono">{lane === "iac" ? `${finding.repository_relative_path || evidence.resource || "Source path withheld"}${evidence.line ? `:${evidence.line}` : ""}` : evidence.resource || finding.packages[0]}</p>
            {evidence.rule && <p className="break-words">Rule: {evidence.rule}</p>}
            {[evidence.provider, evidence.account, evidence.environment].filter(Boolean).length > 0 && <p className="break-words">{[evidence.provider, evidence.account, evidence.environment].filter(Boolean).join(" · ")}</p>}
          </div>
          <div className="min-w-0 space-y-2 text-xs text-ink-secondary">
            {evidence.expected && <p className="break-words">Expected: {evidence.expected}</p>}
            {evidence.observed && <p className="break-words">Observed: {evidence.observed}</p>}
            {evidence.remediation && <p className="break-words">{evidence.remediation}</p>}
            {!evidence.expected && !evidence.observed && !evidence.remediation && <p>Review collector evidence to determine the next step.</p>}
          </div>
          <button type="button" onClick={() => onSelect(vulnRowKey(finding))} className="h-fit w-fit rounded-lg border border-outline px-3 py-1.5 text-xs text-foreground hover:bg-surface">Investigate</button>
        </li>;
      })}
    </ul>
    {findings.length === 0 && <p className="p-8 text-center text-sm text-ink-secondary">No findings match this lane and its filters.</p>}
  </div>;
}
