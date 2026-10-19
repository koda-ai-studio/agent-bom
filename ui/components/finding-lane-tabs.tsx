"use client";
import Link from "next/link";
import { FINDING_LANES, type FindingLane } from "@/lib/finding-lanes";
export function FindingLaneTabs({ lane, counts, approximate, onChange }: {
  lane: FindingLane; counts?: Record<string, number> | undefined; approximate: boolean; onChange: (lane: FindingLane) => void;
}) {
  const current = FINDING_LANES.find((item) => item.key === lane)!;
  return <section aria-label="Finding lanes" className="space-y-3">
    <div role="tablist" aria-label="Finding lanes" className="flex flex-wrap gap-1 rounded-xl border border-outline bg-surface p-1.5">
      {FINDING_LANES.map((item, index) => {
        const count = counts ? item.key === "all" ? Object.values(counts).reduce((a, b) => a + b, 0) : counts[item.key] : undefined;
        return <button key={item.key} role="tab" aria-selected={lane === item.key} aria-controls="finding-lane-results" id={`finding-lane-${item.key}`}
          onClick={() => onChange(item.key)} onKeyDown={(event) => {
            if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
            event.preventDefault();
            const next = event.key === "Home" ? 0 : event.key === "End" ? FINDING_LANES.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + FINDING_LANES.length) % FINDING_LANES.length;
            onChange(FINDING_LANES[next]!.key);
            document.getElementById(`finding-lane-${FINDING_LANES[next]!.key}`)?.focus();
          }} tabIndex={lane === item.key ? 0 : -1}
          className={`rounded-lg px-3 py-2 text-sm transition-colors ${lane === item.key ? "bg-background text-foreground shadow-sm font-semibold" : "text-ink-secondary hover:bg-background"}`}>
          {item.label} <span className="ml-1 text-xs tabular-nums text-ink-tertiary">{count == null ? "—" : `${approximate ? "≥" : ""}${count.toLocaleString()}`}</span>
        </button>;
      })}
    </div>
    <p className="text-xs text-ink-secondary">{current.hint} Tab counts: canonical issues in the current filter scope{approximate ? " (partial; lower bounds)" : ""}.
      {lane === "cloud" && <> Table rows and severity counts group those issues by control; resource occurrences remain expandable.</>}
      {lane === "all" && <> <Link className="underline" href="/">Overview</Link> · <Link className="underline" href="/security-graph">Investigation</Link></>}
    </p>
  </section>;
}
