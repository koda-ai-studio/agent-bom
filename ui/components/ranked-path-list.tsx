"use client";

import { pathSpanLabel } from "@/lib/exposure-path";

export interface RankedPathRow {
  /** Collision-free React key (index-suffixed) for stable list rendering. */
  key: string;
  /** Selection key shared with the command-center panel's selected path. */
  selectionKey: string;
  rank: number;
  title: string;
  cve: string | null;
  riskScore: number;
  nodeCount: number;
  agents: number;
  /** Compact correlated layer sequence, for example agent → server → finding. */
  roleChain?: string | undefined;
  /** MCP tool capability tags (read/write/exec/net) feeding path scoring. */
  capabilityTags?: string[] | undefined;
  /** Environments seen on path hops (prod weighting explainability). */
  environmentTags?: string[] | undefined;
}

function displayPathTitle(row: RankedPathRow): string {
  const title = row.title.trim();
  const cve = row.cve?.trim();
  if (!cve) return title;

  const startsWithCve =
    title.slice(0, cve.length).toLowerCase() === cve.toLowerCase() &&
    (title.length === cve.length || !/[a-z0-9]/i.test(title.charAt(cve.length)));
  if (!startsWithCve) return title;
  return title.slice(cve.length).trimStart().replace(/^[·:—-]\s*/, "") || title;
}

/**
 * Compact, scannable list of ranked exposure paths. One row per path — the
 * DAG for the active row renders once in the command-center panel above, not
 * per-card here, so the surface scales to many paths without a tall stack of
 * duplicate node diagrams. Selecting a row promotes it into that single panel.
 */
export function RankedPathList({
  rows,
  selectedKey,
  onSelect,
  onKeyDown,
  controlsId,
  compact = false,
}: {
  rows: RankedPathRow[];
  selectedKey: string | null;
  onSelect: (key: string) => void;
  onKeyDown?: ((event: React.KeyboardEvent<HTMLDivElement>) => void) | undefined;
  /** Detail region updated by a row selection. */
  controlsId?: string | undefined;
  compact?: boolean;
}) {
  return (
    <div
      className="mt-4 max-h-[28rem] space-y-1.5 overflow-y-auto pr-1 outline-none"
      tabIndex={0}
      onKeyDown={onKeyDown}
      aria-label="Attack path queue"
    >
      {rows.map((row) => {
        const active = row.selectionKey === selectedKey;
        const displayTitle = displayPathTitle(row);
        const advisory = row.cve?.trim() || null;
        if (compact) return <CompactPathRow key={row.key} row={row} active={active} controlsId={controlsId} onSelect={onSelect} />;
        return (
          <button
            key={row.key}
            type="button"
            aria-pressed={active}
            aria-controls={controlsId}
            onClick={() => onSelect(row.selectionKey)}
            className={`flex w-full flex-col items-stretch gap-2 rounded-xl border px-3 py-3 text-left transition ${
              active
                ? "border-orange-400/70 bg-orange-500/10 ring-1 ring-orange-400/60"
                : "border-outline bg-surface-elevated hover:border-outline-strong"
            }`}
          >
            <span className="flex flex-wrap items-center justify-between gap-2">
              <span
                className={`mb-1 inline-flex rounded-md px-2 py-1 text-xs font-semibold uppercase tracking-[0.14em] ${
                  row.rank === 1
                    ? "bg-orange-500/15 text-orange-700 dark:text-orange-300"
                    : "bg-surface text-ink-tertiary"
                }`}
              >
                {row.rank === 1 ? "#1 fix first" : `#${row.rank}`}
              </span>
            <span className="flex items-baseline gap-1.5 text-ink-secondary">
              <span className="text-xs">
                Path priority
              </span>
              <span className="font-mono text-xs font-semibold text-foreground">
                {row.riskScore.toFixed(1)}
              </span>
            </span>
            </span>
            <span className="min-w-0">
              {advisory ? (
                <span
                  data-testid="ranked-path-advisory"
                  className="mb-0.5 block font-mono text-xs font-semibold text-red-700 dark:text-red-200"
                >
                  {advisory}
                </span>
              ) : null}
              <span
                className="line-clamp-3 break-words text-sm font-medium leading-snug text-foreground"
                title={advisory ? `${advisory} · ${displayTitle}` : displayTitle}
              >
                {displayTitle}
              </span>
              <span className="mt-0.5 block text-xs text-ink-tertiary">
                {pathSpanLabel(row.nodeCount)} · {row.agents} agent{row.agents === 1 ? "" : "s"}
              </span>
              {row.roleChain ? (
                <span
                  className="mt-0.5 block truncate font-mono text-xs text-ink-secondary"
                  title={row.roleChain}
                >
                  {row.roleChain}
                </span>
              ) : null}
              {(row.capabilityTags?.length || row.environmentTags?.length) ? (
                <span className="mt-1 flex flex-wrap gap-1">
                  {(row.environmentTags ?? []).slice(0, 2).map((tag) => (
                    <span
                      key={`env-${tag}`}
                      className="rounded border border-sky-500/30 bg-sky-500/10 px-1.5 py-0.5 text-xs font-medium uppercase tracking-[0.12em] text-sky-800 dark:text-sky-200"
                    >
                      {tag}
                    </span>
                  ))}
                  {(row.capabilityTags ?? []).slice(0, 4).map((tag) => (
                    <span
                      key={`cap-${tag}`}
                      className="rounded border border-violet-500/30 bg-violet-500/10 px-1.5 py-0.5 text-xs font-medium uppercase tracking-[0.12em] text-violet-800 dark:text-violet-200"
                    >
                      {tag === "execute" ? "exec" : tag === "network" ? "net" : tag}
                    </span>
                  ))}
                </span>
              ) : null}
            </span>
          </button>
        );
      })}
    </div>
  );
}


function CompactPathRow({ row, active, controlsId, onSelect }: {
  row: RankedPathRow; active: boolean; controlsId?: string | undefined; onSelect: (key: string) => void;
}) {
  const description = [`#${row.rank}`, row.cve, displayPathTitle(row), `Path priority ${row.riskScore.toFixed(1)}`,
    `${pathSpanLabel(row.nodeCount)} · ${row.agents} agents`, row.roleChain, ...(row.environmentTags ?? []), ...(row.capabilityTags ?? [])].filter(Boolean).join(" · ");
  return <button type="button" aria-pressed={active} aria-controls={controlsId} onClick={() => onSelect(row.selectionKey)}
    title={description} aria-label={description}
    className={`block min-h-16 w-full rounded-lg border px-3 py-2 text-left ${active ? "border-orange-400 bg-orange-500/10" : "border-outline bg-surface hover:border-outline-strong"}`}>
    <span className="flex items-baseline gap-2 text-xs">
      <span className="shrink-0 text-ink-secondary">#{row.rank}</span>
      {row.cve ? <span data-testid="ranked-path-advisory" className="font-mono font-semibold text-red-700 dark:text-red-200">{row.cve}</span> : null}
    </span>
    <span className="mt-1 block line-clamp-2 break-words text-sm font-medium leading-snug text-foreground">{displayPathTitle(row)}</span>
    <span className="mt-1 block truncate text-xs text-ink-secondary">{row.roleChain || pathSpanLabel(row.nodeCount)}</span>
  </button>;
}
