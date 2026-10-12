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
  const unknownSyncs = sources ? sources.length - recordedSyncs : 0;
  return <details className="advisory-freshness" aria-label="Advisory data freshness">
    <summary className="advisory-freshness-summary">
      <span className="min-w-0 font-medium text-foreground">Advisory data · {unavailable ? "source status unavailable" : sources === null ? "loading source receipts" : `${sources.length} enabled sources`}</span>
      {sources && <span className="advisory-freshness-counts" aria-label={`${recordedSyncs} recorded sync times, ${unknownSyncs} unknown`}>
        <span>{recordedSyncs} sync {recordedSyncs === 1 ? "time" : "times"} recorded</span><span aria-hidden="true">·</span><span>{unknownSyncs} sync {unknownSyncs === 1 ? "time" : "times"} unknown</span>
      </span>}
    </summary>
    <div className="advisory-freshness-body">
      <p className="text-sm text-ink-secondary">Feed sync receipts are separate from scan time. Missing sync times remain unknown.</p>
      {sources?.length ? <ul className="advisory-source-list" aria-label="Enabled advisory sources">{sources.map(source => {
        const lastSynced = source.feed_run?.last_synced;
        const status = statusLabel(source.feed_run?.status);
        return <li key={source.source_id} className="advisory-source-row">
          <div className="min-w-0">
            <p className="font-medium text-foreground">{source.display_name}</p>
            <p className="mt-1 text-xs text-ink-tertiary">Last feed sync · {formatSyncTime(lastSynced)}</p>
          </div>
          <div className="flex flex-wrap items-center justify-end gap-2">
            <span className="advisory-source-status" data-status={source.feed_run?.status || "unknown"}>{status}</span>
            {source.feed_run?.cap_hit && <span className="advisory-source-note">Partial feed</span>}
            {!!source.feed_run?.validation_failures && <span className="advisory-source-note">{source.feed_run.validation_failures} validation failures</span>}
          </div>
        </li>;
      })}</ul> : sources && <p role="note" className="advisory-source-empty">No enabled source receipts were returned. This does not establish current advisory coverage.</p>}
      <Link href="/integrations?tab=intel" className="advisory-source-link">Inspect advisory sources</Link>
    </div>
  </details>;
}
