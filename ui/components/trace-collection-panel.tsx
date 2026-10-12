"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import type { TraceCollectionReceipt } from "@/lib/api-types";

const failures: Record<string, string> = {
  rate_limited: "Provider rate limit. Wait before resuming.",
  access_denied: "Provider access denied. Ask your operator to restore access before retrying.",
  unsupported_api: "This connection requires Langfuse v2 observations support.",
  provider_unavailable: "Provider unavailable. Saved progress is retained.",
  provider_timeout: "Provider timed out. Saved progress is retained.",
  connection_or_evidence_conflict: "Connection changed or evidence conflicted. Ask your operator to inspect the collection.",
};

export function TraceCollectionPanel({ connectionId }: { connectionId: string }) {
  const [state, setState] = useState<TraceCollectionReceipt | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState(false);
  const [remaining, setRemaining] = useState(0);
  const generation = useRef(0);
  const request = useRef<AbortController | null>(null);
  useEffect(() => {
    let active = true;
    const epoch = ++generation.current;
    const controller = new AbortController(); request.current = controller;
    api.traceCollectionStatus(connectionId, controller.signal)
      .then(value => { if (active && epoch === generation.current) { setState(value); setRemaining(value.retry_after_seconds ?? 0); } })
      .catch(() => { if (active && epoch === generation.current) setError(true); });
    return () => { active = false; controller.abort(); };
  }, [connectionId]);
  useEffect(() => {
    const timer = setInterval(() => setRemaining(value => Math.max(0, value - 1)), 1000);
    return () => clearInterval(timer);
  }, []);
  async function collect() {
    const controller = request.current;
    if (!controller || controller.signal.aborted || pending) return;
    generation.current += 1;
    setPending(true); setError(false);
    try {
      const value = await api.collectTracePage(connectionId, controller.signal);
      if (!controller.signal.aborted) { setState(value); setRemaining(value.retry_after_seconds ?? 0); }
    } catch {
      if (!controller.signal.aborted) {
        setError(true);
        try {
          const value = await api.traceCollectionStatus(connectionId, controller.signal);
          if (!controller.signal.aborted) { setState(value); setRemaining(value.retry_after_seconds ?? 0); }
        } catch { /* The prior receipt stays visible; it is not a success claim. */ }
      }
    } finally { if (!controller.signal.aborted) setPending(false); }
  }
  return <section aria-label="Saved trace collection" className="space-y-3 rounded-lg border border-[var(--border-subtle)] p-4">
    <h3 className="font-semibold">Incremental collection</h3>
    <p className="text-sm text-[var(--text-secondary)]">Collect up to 100 native observations per request into your trace explorer. Each request resumes saved progress. Collection runs when requested.</p>
    {state && <>
      <p role="status" className="text-sm">{state.persisted ?? 0} new observations saved · {state.pages ?? 0} pages committed</p>
      <p className="text-xs text-[var(--text-secondary)]">{state.status === "caught_up" ? "Selected window collected." : state.status === "not_started" ? "Ready to collect the previous day, with a 15-minute ingestion delay." : "Collection is incomplete."} This does not establish workload identity or complete provider coverage.</p>
      {state.completed_until && <p className="break-all text-xs">Collected through {state.completed_until}{state.lag_seconds != null ? ` · ${Math.ceil(state.lag_seconds / 60)} minutes behind at last check` : ""}</p>}
      {state.last_error && <p role="alert" className="text-sm text-amber-800 dark:text-amber-200">{failures[state.last_error] ?? "Provider evidence could not be accepted. Saved progress is retained; ask your operator to inspect the connection."}</p>}
    </>}
    {error && <p role="alert" className="text-sm text-red-700 dark:text-red-300">Collection could not be confirmed. Check connection status and retry; committed progress is preserved.</p>}
    {remaining > 0 && <p className="text-sm">Retry available in {remaining} seconds.</p>}
    <button type="button" disabled={pending || remaining > 0} onClick={() => void collect()} className="rounded-lg bg-emerald-700 px-4 py-2 text-sm font-medium text-white disabled:opacity-50">{pending ? "Saving evidence…" : "Collect next page"}</button>
    <Link href="/traces" className="ml-3 inline-block text-sm underline text-emerald-800 dark:text-emerald-300">Open trace explorer</Link>
  </section>;
}
