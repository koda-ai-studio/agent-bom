"use client";

import { formatFindingTimestamp } from "@/lib/findings-view";

export type FindingStatusFilter = "open" | "resolved" | "all";

export const FINDING_STATUS_LABELS: Record<FindingStatusFilter, string> = {
  open: "Open",
  resolved: "Resolved",
  all: "All statuses",
};

/** The URL value, falling back to the live-posture default for anything unknown. */
export function parseFindingStatus(value: string | null): FindingStatusFilter {
  return value === "resolved" || value === "all" ? value : "open";
}

export function FindingStatusSelect({ value, onChange }: { value: FindingStatusFilter; onChange: (value: FindingStatusFilter) => void }) {
  return (
    <label className="flex items-center gap-2 text-xs text-ink-secondary">
      Status
      <select
        aria-label="Finding status"
        value={value}
        onChange={(event) => onChange(parseFindingStatus(event.target.value))}
        className="rounded-lg border border-outline bg-surface px-2 py-1.5 text-foreground"
      >
        {(Object.keys(FINDING_STATUS_LABELS) as FindingStatusFilter[]).map((key) => (
          <option key={key} value={key}>{FINDING_STATUS_LABELS[key]}</option>
        ))}
      </select>
    </label>
  );
}

export function LifecycleDate({ label, value }: { label: string; value: string | null | undefined }) {
  if (!value || Number.isNaN(Date.parse(value))) return null;
  const exact = formatFindingTimestamp(value);
  const date = new Date(value).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  return <time dateTime={value} title={exact} aria-label={`${label}: ${exact}`} className="whitespace-nowrap">{label}: {date}</time>;
}

/** "1 of 2 open" for an issue spanning assets; nothing when one count alone tells the story. */
export function openOccurrenceLabel(open: number | undefined, resolved: number | undefined): string | null {
  if (typeof open !== "number" || typeof resolved !== "number" || resolved === 0 || open === 0) return null;
  return `${open} of ${open + resolved} open`;
}
