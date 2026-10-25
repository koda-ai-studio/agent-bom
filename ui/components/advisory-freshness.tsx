"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api, type IntelSource } from "@/lib/api";

function statusLabel(status: string | null | undefined): string {
  if (status === "freshness_unknown") return "Freshness unknown";
  if (status === "synced") return "Synced";
  if (status === "not_synced") return "Not synced";
  if (!status) return "Status unknown";
  return status.replaceAll("_", " ").replace(/^\w/, value => value.toUpperCase());
}

function formatSyncTime(value: string | null | undefined): string {
  if (!value) return "Not recorded";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return `${new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(parsed)} UTC`;
}

/** Matches the advisory DB's default staleness threshold (vuln_freshness.DEFAULT_MAX_AGE_HOURS). */
const STALE_AFTER_HOURS = 24;

type SourceHealth = { status: string; label: string };

function ageLabel(hours: number): string {
  if (hours < 48) return `${hours} hours old`;
  return `${Math.floor(hours / 24)} days old`;
}

/** Per-source state: a partial sync is never shown as synced, and an old sync is stale. */
function sourceHealth(source: IntelSource, now: number): SourceHealth {
  const run = source.feed_run;
  if (run?.status === "partial") {
    const reason = run.partial_reason ? run.partial_reason.replaceAll("_", " ") : "reason not recorded";
    return { status: "partial", label: `Partial (${reason})` };
  }
  const synced = run?.last_synced ? new Date(run.last_synced).getTime() : Number.NaN;
  if (run?.status === "synced" && !Number.isNaN(synced)) {
    const hours = Math.floor((now - synced) / 3_600_000);
    if (hours > STALE_AFTER_HOURS) return { status: "stale", label: `Stale · ${ageLabel(hours)}` };
  }
  return { status: run?.status || "unknown", label: statusLabel(run?.status) };
}

/** One phrase for the feed sync state: which sources synced, and which are partial, stale or never recorded. */
function syncSummary(recorded: number, total: number, partial: number, stale: number): string {
  const issues = [partial ? `${partial} partial` : "", stale ? `${stale} stale` : ""].filter(Boolean);
  if (recorded === 0) return "No feed sync recorded yet";
  const base = recorded === total ? (issues.length ? "All recorded" : "All synced") : `${recorded} of ${total} synced · ${total - recorded} never recorded`;
  return [base, ...issues].join(" · ");
}

/** Feed sync receipts describe advisory data, independently of scan timestamps. */
export function AdvisoryFreshness() {
  const [sources, setSources] = useState<IntelSource[] | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const result = await api.getIntelSources();
        if (active) setSources(result.sources.filter(source => source.enabled));
      } catch {
        if (active) setUnavailable(true);
      }
    }
    void load();
    return () => { active = false; };
  }, []);
  const recordedSyncs = sources?.filter(source => Boolean(source.feed_run?.last_synced)).length ?? 0;
  const now = Date.now();
  const health = new Map((sources ?? []).map(source => [source.source_id, sourceHealth(source, now)]));
  const healthCount = (status: string) => [...health.values()].filter(item => item.status === status).length;
  return <details className="advisory-freshness" aria-label="Advisory data freshness">
    <summary className="advisory-freshness-summary">
      <span className="min-w-0 font-medium text-foreground">Advisory data · {unavailable ? "source status unavailable" : sources === null ? "loading source receipts" : `${sources.length} enabled ${sources.length === 1 ? "source" : "sources"}`}</span>
      {sources?.length ? <span className="advisory-freshness-counts">{syncSummary(recordedSyncs, sources.length, healthCount("partial"), healthCount("stale"))}</span> : null}
    </summary>
    <div className="advisory-freshness-body">
      <p className="text-sm text-ink-secondary">Feed sync receipts are separate from scan time. Missing sync times remain unknown.</p>
      {sources?.length ? <ul className="advisory-source-list" aria-label="Enabled advisory sources">{sources.map(source => {
        const lastSynced = source.feed_run?.last_synced;
        const state = health.get(source.source_id) ?? { status: "unknown", label: statusLabel(null) };
        return <li key={source.source_id} className="advisory-source-row" aria-label={source.display_name}>
          <div className="min-w-0">
            <p className="font-medium text-foreground">{source.display_name}</p>
            <p className="mt-1 text-xs text-ink-tertiary">Last feed sync · {formatSyncTime(lastSynced)}</p>
          </div>
          <div className="flex flex-wrap items-center justify-end gap-2">
            <span className="advisory-source-status" data-testid="source-status" data-status={state.status}>{state.label}</span>
            {source.feed_run?.cap_hit && state.status !== "partial" && <span className="advisory-source-note">Partial feed</span>}
            {!!source.feed_run?.validation_failures && <span className="advisory-source-note">{source.feed_run.validation_failures} validation failures</span>}
          </div>
        </li>;
      })}</ul> : sources && <p role="note" className="advisory-source-empty">No enabled source receipts were returned. This does not establish current advisory coverage.</p>}
      <Link href="/integrations?tab=intel" className="advisory-source-link">Inspect advisory sources</Link>
    </div>
  </details>;
}
