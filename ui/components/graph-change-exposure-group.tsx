"use client";

import { useState, type ReactNode } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";

/** Rows per page in one exposure group; the API returns at most its top 10 by risk. */
export const EXPOSURE_PAGE_SIZE = 5;

export interface ExposureGroupProps<T> {
  title: string;
  count: number;
  lowerBound?: boolean | undefined;
  tone: "added" | "removed";
  rows: T[];
  rowKey: (row: T) => string;
  renderRow: (row: T) => ReactNode;
  /** Opens the paged full diff for rows beyond the returned top rows. */
  onOpenDiff?: (() => void) | undefined;
}

function rangeLabel(start: number, end: number, returned: number, truncated: boolean): string {
  const of = truncated ? `top ${returned} by risk` : `${returned}`;
  if (returned > EXPOSURE_PAGE_SIZE) return `${start + 1}–${end} of ${of}`;
  return truncated ? `Top ${returned} by risk` : "";
}

function Pager({ title, page, pages, onPage }: { title: string; page: number; pages: number; onPage: (page: number) => void }) {
  const noun = title.toLowerCase();
  return (
    <span className="inline-flex items-center gap-0.5">
      <button type="button" aria-label={`Previous ${noun} page`} disabled={page === 0} onClick={() => onPage(page - 1)}
        className="rounded p-0.5 text-foreground hover:bg-surface-elevated disabled:cursor-not-allowed disabled:opacity-40">
        <ChevronLeft aria-hidden className="h-3.5 w-3.5" />
      </button>
      <button type="button" aria-label={`Next ${noun} page`} disabled={page >= pages - 1} onClick={() => onPage(page + 1)}
        className="rounded p-0.5 text-foreground hover:bg-surface-elevated disabled:cursor-not-allowed disabled:opacity-40">
        <ChevronRight aria-hidden className="h-3.5 w-3.5" />
      </button>
    </span>
  );
}

/** One exposure group: its total, a bounded page of the returned rows, and a way to the full diff beyond them. */
export function ExposureGroup<T>({ title, count, lowerBound, tone, rows, rowKey, renderRow, onOpenDiff }: ExposureGroupProps<T>) {
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(rows.length / EXPOSURE_PAGE_SIZE));
  const current = Math.min(page, pages - 1);
  const start = current * EXPOSURE_PAGE_SIZE;
  const end = Math.min(rows.length, start + EXPOSURE_PAGE_SIZE);
  const truncated = count > rows.length || Boolean(lowerBound);
  const total = `${count.toLocaleString()}${lowerBound ? "+" : ""}`;
  const range = rangeLabel(start, end, rows.length, truncated);
  return (
    <div role="group" aria-label={title} className="space-y-1">
      <p className={`text-xs font-medium ${tone === "added" ? "text-red-700 dark:text-red-200" : "text-emerald-700 dark:text-emerald-300"}`}>
        {title} · {total}
      </p>
      <ul className="space-y-1">{rows.slice(start, end).map(row => <li key={rowKey(row)}>{renderRow(row)}</li>)}</ul>
      {(range || truncated) && (
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-ink-tertiary">
          {range && <span className="tabular-nums">{range}{truncated ? ` · ${total} total` : ""}</span>}
          {pages > 1 && <Pager title={title} page={current} pages={pages} onPage={setPage} />}
          {truncated && onOpenDiff && (
            <button type="button" onClick={onOpenDiff} aria-label={`Open the full diff for all ${total} ${title.toLowerCase()}`}
              className="text-foreground underline underline-offset-4">Open full diff</button>
          )}
        </div>
      )}
    </div>
  );
}
