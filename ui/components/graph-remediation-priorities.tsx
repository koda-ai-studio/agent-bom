import Link from "next/link";

import type { FixFirstGraphViewResponse } from "@/lib/api-contracts/graph-views";
import { countLabel, formatCount } from "@/lib/count-label";

/** Server-ranked coverage of recorded guidance, never a simulated or verified fix. */
export function GraphRemediationPriorities({ view, scanId }: { view: FixFirstGraphViewResponse | null; scanId: string }) {
  const priorities = scanId && view?.scan_id === scanId ? view.remediation_priorities : undefined;
  // No recorded priorities for this snapshot: show nothing rather than a dead bar.
  if (!priorities) return null;
  return <details className="group rounded-xl border border-outline bg-surface">
    <summary className="flex min-h-11 cursor-pointer flex-wrap items-center justify-between gap-2 px-4 py-3 text-sm">
      <span className="font-semibold text-foreground">Prioritize fixes</span>
      <span className="text-xs text-ink-secondary">{prioritySummary(priorities)}</span>
    </summary>
    <div className="border-t border-outline p-4"><PriorityDetails priorities={priorities} scanId={scanId} /></div>
  </details>;
}

type Priorities = NonNullable<FixFirstGraphViewResponse["remediation_priorities"]>;

/** "1,133 candidates · 5,000 of 7,005 paths assessed · capped": the cap is named in the collapsed header. */
function prioritySummary(priorities: Priorities): string {
  const { assessed_paths: assessed, total_paths: total } = priorities;
  const paths = typeof total === "number" && total > assessed
    ? `${formatCount(assessed)} of ${formatCount(total)} paths assessed`
    : `${formatCount(assessed)} paths assessed`;
  const capped = priorities.limitations.includes("path_budget") ? " · capped" : "";
  return `${countLabel(priorities.candidate_count, "candidate")} · ${paths}${capped}`;
}

function PriorityDetails({ priorities, scanId }: { priorities: Priorities; scanId: string }) {
  return (
    <section aria-label="Shared remediation priorities" className="space-y-4">
      <div>
        <h3 className="text-base font-semibold text-foreground">Which fix should I review first?</h3>
        <p className="mt-1 text-sm text-ink-secondary">Ranked by additional critical, high, then total recorded paths touching each finding. Shared paths count once across selections.</p>
        <p className="mt-2 text-xs text-ink-secondary">{formatCount(priorities.assessed_paths)} paths assessed · {formatCount(priorities.candidate_count)} candidates · {formatCount(priorities.remaining_paths)} paths outside these recommendations.</p>
      </div>
      <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-800 dark:text-amber-100">
        Recorded guidance requires review. Coverage does not predict paths removed or prove a fix. Source collection completeness is not assessed; rescan and verify changes.
        {!priorities.complete && <> Assessment limited: {priorities.limitations.map(reason => reason.replaceAll("_", " ")).join(", ")}.</>}
      </p>
      {priorities.recommendations.length === 0 ? (
        <p className="text-sm text-ink-secondary">No applicable recorded guidance was found on the assessed paths. This is not a clean verdict.</p>
      ) : <ol className="space-y-3">
        {priorities.recommendations.map(item => {
          const query = new URLSearchParams({ scan: scanId, node: item.finding_node_id });
          const workflow = new URLSearchParams({ view: "verification", scan: scanId });
          if (item.finding_id) workflow.set("finding", item.finding_id);
          return <li key={item.id} className="rounded-xl border border-outline bg-surface p-4">
            <h4 className="break-words text-sm font-semibold text-foreground">{item.rank}. {item.finding_label} · {item.asset_label}</h4>
            <p className="mt-2 break-words text-sm text-ink-secondary">{item.guidance}</p>
            <dl className="mt-3 grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
              <div><dt className="text-xs text-ink-secondary">Paths touching finding</dt><dd className="font-semibold">{formatCount(item.covered_paths)}</dd></div>
              <div><dt className="text-xs text-ink-secondary">Additional coverage</dt><dd className="font-semibold">{formatCount(item.newly_covered_paths)}</dd></div>
              <div><dt className="text-xs text-ink-secondary">Critical / high</dt><dd className="font-semibold">{formatCount(item.critical_paths)} / {formatCount(item.high_paths)}</dd></div>
              <div><dt className="text-xs text-ink-secondary">Reachability unknown</dt><dd className="font-semibold">{formatCount(item.unknown_reachability_paths)}</dd></div>
            </dl>
            <p className="mt-2 text-xs text-ink-secondary">{formatCount(item.remaining_paths_after_selection)} assessed paths remain outside this and earlier recommendations.</p>
            <div className="mt-3 flex flex-wrap gap-2">
              <Link className="graph-page-secondary-action" href={`/security-graph?${query}`}>Review path evidence</Link>
              <Link className="graph-page-secondary-action" href={`/remediation?${workflow}#campaigns`}>Open verification workflow</Link>
            </div>
          </li>;
        })}
      </ol>}
    </section>
  );
}
