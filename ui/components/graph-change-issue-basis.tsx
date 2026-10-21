import type { GraphEstateIssueChange } from "@/lib/api-types";

const delta = (value: number) => (value === 0 ? "no change" : `${value > 0 ? "+" : "−"}${Math.abs(value).toLocaleString()}`);

/** The posture trend's open-issue counts for the pair, so graph-node counts are never read against the trend's unit. */
export function GraphChangeIssueBasis({ change }: { change?: GraphEstateIssueChange | null | undefined }) {
  if (!change) return null;
  const part = (key: "critical" | "high") =>
    `${key} ${change.old[key].toLocaleString()} → ${change.new[key].toLocaleString()} (${delta(change.new[key] - change.old[key])})`;
  return (
    <p data-testid="graph-changes-issue-basis" className="text-xs text-ink-secondary [overflow-wrap:anywhere]">
      Open issues, the posture trend&apos;s unit: {part("critical")} · {part("high")}
    </p>
  );
}
