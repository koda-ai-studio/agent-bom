"use client";

import { formatFindingTimestamp } from "@/lib/findings-view";

export type FindingStatusFilter = "open" | "stale" | "resolved" | "all";

export const FINDING_STATUS_LABELS: Record<FindingStatusFilter, string> = {
  open: "Open",
  stale: "Stale",
  resolved: "Resolved",
  all: "All statuses",
};

/** The URL value, falling back to the live-posture default for anything unknown. */
export function parseFindingStatus(value: string | null): FindingStatusFilter {
  return value === "stale" || value === "resolved" || value === "all" ? value : "open";
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

const RESOLUTION_REASON_LABELS: Record<string, string> = {
  no_longer_detected: "No longer detected",
  asset_deleted: "Asset deleted",
};

export function resolutionReasonLabel(reason: string | null | undefined): string | null {
  return reason ? RESOLUTION_REASON_LABELS[reason] ?? null : null;
}

export function lifecycleSummary(finding: {
  lifecycle_status?: string | undefined;
  resolved_at?: string | undefined;
  resolution_reason?: string | null | undefined;
  stale?: boolean | undefined;
}): string | null {
  const stale = finding.stale ? " · stale" : "";
  switch (finding.lifecycle_status) {
    case "open": return `Open${stale}`;
    case "reopened": return `Reopened${stale}`;
    case "resolved":
      if (!finding.resolved_at) return "Reported resolved · verification not provided";
      return `Resolved · ${(resolutionReasonLabel(finding.resolution_reason) ?? "No longer detected").toLowerCase()}`;
    case "suppressed": return "Suppressed · not verified fixed";
    default: return null;
  }
}
