import { ownershipSummary, type OwnershipFields } from "@/lib/finding-ownership";
import { nowForRelativeTime } from "@/lib/relative-clock";

/** Owner/team and remediation SLA for a top risk, on the card itself. */
export function RiskOwnershipLine({ ownership, now = nowForRelativeTime() }: { ownership: OwnershipFields | undefined; now?: number }) {
  if (!ownership) return null;
  const summary = ownershipSummary(ownership, now);
  const slaTone = summary.slaState === "overdue" ? "font-semibold text-red-700 dark:text-red-300" : "text-foreground";
  return (
    <p className="flex flex-wrap items-baseline gap-x-3 gap-y-1 text-xs text-ink-secondary">
      <span>Owner <span className={summary.owner ? "font-medium text-foreground" : "font-medium text-amber-800 dark:text-amber-300"}>{summary.ownerLabel}</span></span>
      <span>
        SLA <span className={slaTone}>{summary.slaLabel}</span>
        {summary.dueDate ? <span> · {new Date(summary.dueDate).toLocaleDateString()}</span> : null}
      </span>
    </p>
  );
}
