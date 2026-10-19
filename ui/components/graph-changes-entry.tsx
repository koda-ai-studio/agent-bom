"use client";

import { GitCompare, Loader2 } from "lucide-react";

export interface GraphChangesEntryProps {
  headline: string | null;
  loading: boolean;
  error: string | null;
  highlighting: boolean;
  /** What the counts are measured against, e.g. "previous scans" or "previous snapshot". */
  baseline?: string;
  onOpen: () => void;
  onClearHighlight: () => void;
}

/** Status-bar entry for "what changed?"; never blocks the first frame. */
export function GraphChangesEntry({
  headline,
  loading,
  error,
  highlighting,
  baseline = "previous scans",
  onOpen,
  onClearHighlight,
}: GraphChangesEntryProps) {
  const text = loading && !headline ? "Checking changes…" : error && !headline ? "Changes unavailable" : headline;
  if (!text) return null;
  return (
    <div data-testid="graph-changes-entry" className="flex min-w-0 max-w-full items-center gap-2 text-xs text-muted-foreground">
      <button
        type="button"
        onClick={onOpen}
        aria-label={`Changed since ${baseline}: ${text}`}
        aria-haspopup="dialog"
        className="inline-flex min-h-7 min-w-0 items-center gap-1.5 rounded-md px-1 text-left text-foreground underline-offset-4 hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2"
      >
        {loading && !headline ? (
          <Loader2 aria-hidden className="h-3.5 w-3.5 shrink-0 animate-spin text-ink-tertiary" />
        ) : (
          <GitCompare aria-hidden className="h-3.5 w-3.5 shrink-0 text-sky-600 dark:text-sky-300" />
        )}
        <span className="shrink-0 text-ink-secondary">Changes</span>
        <span className="min-w-0 font-medium tabular-nums sm:truncate">{text}</span>
      </button>
      {highlighting && (
        <button type="button" onClick={onClearHighlight} className="shrink-0 text-foreground underline underline-offset-4" aria-label="Clear highlight">
          Clear highlight
        </button>
      )}
    </div>
  );
}
