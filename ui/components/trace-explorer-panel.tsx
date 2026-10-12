"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, ChevronRight, Loader2, ShieldAlert } from "lucide-react";

import { api } from "@/lib/api";
import type { TraceExplorerResponse } from "@/lib/api-types";

const TRACE_LIMIT = 120;

export function TraceExplorerPanel({ agent, scanId }: { agent?: string | undefined; scanId?: string | undefined }) {
  const [source, setSource] = useState("");
  const [page, setPage] = useState<{ agent: string | undefined; offset: number }>({ agent, offset: 0 });
  const offset = page.agent === agent ? page.offset : 0;
  const [data, setData] = useState<TraceExplorerResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [selectedSpanId, setSelectedSpanId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const response = await api.getTraceExplorer(TRACE_LIMIT, scanId, { offset, agent_name: agent, source: source || undefined });
        if (!cancelled) {
          setData(response);
          const firstSession = response.sessions[0];
          const firstSpan = firstSession?.spans[0];
          setSelectedSessionId(firstSession?.session_id ?? null);
          setSelectedSpanId(firstSpan?.span_id ?? null);
        }
      } catch {
        if (!cancelled) setError("Unable to load activity. Retry after checking the connection.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [scanId, agent, offset, source]);

  const sessions = useMemo(() => {
    if (!agent) return data?.sessions ?? [];
    return (data?.sessions ?? []).flatMap((session) => {
      // Sessions can contain multiple actors. Never infer span ownership from
      // the session's first actor or use partial/case-insensitive matching.
      const spans = session.spans.filter((span) => span.agent === agent);
      return spans.length ? [{ ...session, agent, spans,
        blocked_count: spans.filter((span) => span.verdict === "blocked").length,
      }] : [];
    });
  }, [agent, data]);
  const selectedSession = sessions.find((session) => session.session_id === selectedSessionId) ?? sessions[0] ?? null;
  const selectedSpan = selectedSession?.spans.find((span) => span.span_id === selectedSpanId) ?? selectedSession?.spans[0] ?? null;
  const blockedCount = sessions.reduce((count, session) => count + session.blocked_count, 0);
  const scopeNotice = <div role="note" aria-label="Activity evidence scope" className="mb-4 space-y-1 rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] p-3 text-xs text-[var(--text-secondary)]">
    <p>{agent ? `Agent: ${agent} · exact recorded name match` : "All recorded agent identities in this response"}</p>
    {data?.retained_total !== undefined ? <p>{data.retained_total} matching retained observations · page {Math.floor(offset / TRACE_LIMIT) + 1}. Counts describe stored evidence, not complete provider history.{data.feed_included ? " The first page also includes a bounded gateway feed." : ""}</p> : <p>Bounded sample: requests up to {TRACE_LIMIT} records per source. This is not a complete activity history.</p>}
    <div className="flex flex-wrap items-center gap-3 pt-2">
      <label className="flex items-center gap-2">Activity source
        <select aria-label="Activity source" value={source} onChange={(event) => { setSource(event.target.value); setPage({ agent, offset: 0 }); }} className="rounded border border-outline bg-surface px-2 py-1 text-ink-primary">
          <option value="">All sources</option>
          {Array.from(new Set(["langfuse", "langsmith", ...Object.keys(data?.source_counts ?? {}), ...(source ? [source] : [])])).map((item) => <option key={item} value={item}>{item}</option>)}
        </select>
      </label>
      {data?.retained_total !== undefined && <>
        <button type="button" aria-label="Previous activity page" disabled={loading || offset === 0} onClick={() => setPage({ agent, offset: Math.max(0, offset - TRACE_LIMIT) })} className="underline disabled:opacity-40">Previous</button>
        <button type="button" aria-label="Next activity page" disabled={loading || !data.has_more} onClick={() => setPage({ agent, offset: offset + TRACE_LIMIT })} className="underline disabled:opacity-40">Next</button>
      </>}
    </div>
    {scanId && <p>Inventory identifiers are checked against snapshot {scanId}. Matching an identifier does not establish invocation, current access, or exploitation.</p>}
  </div>;

  if (loading) {
    return (
      <>{scopeNotice}<div className="flex items-center gap-2 rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/50 px-4 py-10 text-sm text-[var(--text-secondary)]">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading runtime trace explorer…
      </div></>
    );
  }

  if (error) {
    return (
      <>{scopeNotice}<div role="alert" className="rounded-2xl border border-red-500/30 dark:border-red-900/50 bg-red-500/10 dark:bg-red-950/30 px-4 py-3 text-sm text-red-700 dark:text-red-300">
        Activity unavailable: {error}
      </div></>
    );
  }

  if (!data || sessions.length === 0) {
    return (
      <>{scopeNotice}<div className="rounded-2xl border border-dashed border-[var(--border-subtle)] bg-[var(--surface)]/40 px-4 py-10 text-center text-sm text-[var(--text-tertiary)]">
        {agent ? "No activity matched this agent in the retrieved records." : "No runtime activity records were returned."} Activity outside this sample is unknown; this does not prove that no activity occurred.
      </div></>
    );
  }

  return (
    <>{scopeNotice}<div className="grid gap-4 xl:grid-cols-[280px_minmax(0,1fr)_320px]">
      <section className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-4">
        <h2 className="text-sm font-semibold text-[var(--foreground)]">Sessions</h2>
        <p className="mt-1 text-xs text-[var(--text-tertiary)]">{sessions.length} sessions · {blockedCount} blocked spans</p>
        <div className="mt-4 space-y-2">
          {sessions.map((session) => (
            <button
              key={session.session_id}
              type="button"
              onClick={() => {
                setSelectedSessionId(session.session_id);
                setSelectedSpanId(session.spans[0]?.span_id ?? null);
              }}
              className={`w-full rounded-xl border px-3 py-2 text-left transition-colors ${
                selectedSessionId === session.session_id
                  ? "border-emerald-700/60 bg-emerald-950/30"
                  : "border-[var(--border-subtle)] bg-[var(--background)]/60 hover:border-[var(--border-subtle)]"
              }`}
            >
              <div className="text-sm font-medium text-[var(--foreground)]">{session.agent || session.session_id}</div>
              <div className="mt-1 text-xs text-[var(--text-tertiary)]">
                {session.spans.length} spans · {session.blocked_count} blocked
              </div>
            </button>
          ))}
        </div>
      </section>

      <section className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-4">
        <h2 className="text-sm font-semibold text-[var(--foreground)]">Flow</h2>
        <p className="mt-1 text-xs text-[var(--text-tertiary)]">Recorded spans and physical parent relationships.</p>
        <div className="mt-4 space-y-2">
          {(selectedSession?.spans ?? []).map((span) => (
            <button
              key={span.span_id}
              type="button"
              onClick={() => setSelectedSpanId(span.span_id)}
              style={{ paddingInlineStart: `${12 + Math.min(span.depth ?? 0, 8) * 16}px` }}
              className={`flex w-full items-center gap-3 rounded-xl border px-3 py-3 text-left transition-colors ${
                selectedSpanId === span.span_id
                  ? "border-sky-700/60 bg-sky-950/20"
                  : "border-[var(--border-subtle)] bg-[var(--background)]/60 hover:border-[var(--border-subtle)]"
              }`}
            >
              <span
                className={`inline-flex h-8 w-8 items-center justify-center rounded-full border ${
                  span.verdict === "blocked"
                    ? "border-rose-800 bg-rose-950 text-rose-300"
                    : "border-sky-800 bg-sky-950 text-sky-300"
                }`}
              >
                {span.verdict === "blocked" ? <ShieldAlert className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate font-mono text-xs text-[var(--foreground)]">{span.native_name || span.tool || span.action_type}</span>
                <span className="mt-1 block text-[11px] text-[var(--text-tertiary)]">{span.event_time_missing ? "Event time unavailable" : span.timestamp || "—"} · {span.verdict}{span.parent_state === "missing" ? " · Parent outside this sample" : span.parent_state === "cycle" ? " · Cyclic parent evidence" : ""}</span>
              </span>
            </button>
          ))}
        </div>
      </section>

      <section className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-4">
        <h2 className="text-sm font-semibold text-[var(--foreground)]">Detail</h2>
        {!selectedSpan ? (
          <p className="mt-4 text-sm text-[var(--text-tertiary)]">Select a span to inspect policy and finding joins.</p>
        ) : (
          <div className="mt-4 space-y-4 text-sm">
            <div>
              <div className="text-[11px] uppercase tracking-wide text-[var(--text-tertiary)]">Tool call</div>
              <div className="mt-1 font-mono text-[var(--foreground)]">{selectedSpan.native_name || selectedSpan.tool || selectedSpan.action_type}</div>
              <div className="mt-2 text-xs text-[var(--text-secondary)]">{selectedSpan.detail}</div>
            </div>
            {selectedSpan.surface === "imported_trace" && <>
              <p className="text-xs text-ink-secondary">Imported {selectedSpan.native_type || "native"} span · {selectedSpan.source_scope?.provider}. A successful span does not prove exploitation or data access.</p>
              <details className="border-t border-outline pt-2"><summary className="cursor-pointer text-xs">Source and parent evidence</summary>
                <dl className="mt-2 space-y-1 break-words text-xs text-ink-secondary">
                  {Object.entries(selectedSpan.source_scope ?? {}).filter(([, value]) => value).map(([key, value]) => <div key={key}><dt className="inline font-medium">{key.replaceAll("_", " ")}: </dt><dd className="inline">{value}</dd></div>)}
                  <div><dt className="inline font-medium">Physical parent: </dt><dd className="inline">{selectedSpan.parent_span_id || "No parent recorded"}</dd></div>
                  {selectedSpan.logical_root != null && <div>Logical root: {selectedSpan.logical_root ? "Yes" : "No"}</div>}
                  <div>Collected: {selectedSpan.collected_at || "Unknown"}</div>
                </dl>
              </details>
              {selectedSpan.inventory_binding && <div className="border-t border-outline pt-2 text-xs text-ink-secondary">
                {selectedSpan.inventory_binding.state === "exact_identifier" && selectedSpan.inventory_binding.node_id && selectedSpan.inventory_binding.scan_id ? <>
                  <a className="underline" href={`/security-graph?lens=estate&scan=${encodeURIComponent(selectedSpan.inventory_binding.scan_id)}&root=${encodeURIComponent(selectedSpan.inventory_binding.node_id)}&investigate=1`}>Inspect reported inventory entity</a>
                  <p className="mt-1">Exact source-reported identifier and scope match. Workload identity and execution are not independently verified.</p>
                  {!!selectedSpan.inventory_binding.inventory_paths?.length && <div className="mt-3 space-y-2">
                    <p>Inventory relationships do not prove this span executed a package or reached a vulnerability.</p>
                    <ul className="space-y-2">{selectedSpan.inventory_binding.inventory_paths.map(path => <li key={path.finding_node_id}>
                      <p className="break-words">{path.node_labels.join(" → ")}</p>
                      <a className="underline" href={`/security-graph?lens=estate&scan=${encodeURIComponent(selectedSpan.inventory_binding!.scan_id!)}&root=${encodeURIComponent(path.finding_node_id)}&investigate=1`}>Inspect recorded finding path</a>
                    </li>)}</ul>
                    <p>Bounded inventory paths{selectedSpan.inventory_binding.paths_truncated ? "; additional paths may be omitted" : ""}.</p>
                  </div>}

                </> : <p>Inventory mapping: {selectedSpan.inventory_binding.state.replaceAll("_", " ")}. No exact entity link established.</p>}
              </div>}
              <TraceSpanHistory key={selectedSpan.span_id} observationId={selectedSpan.span_id} />
            </>}
            <div className="flex flex-wrap gap-2">
              <span className={`rounded border px-2 py-0.5 text-xs uppercase ${
                selectedSpan.verdict === "blocked"
                  ? "border-rose-800 bg-rose-950 text-rose-300"
                  : "border-sky-800 bg-sky-950 text-sky-300"
              }`}>
                {selectedSpan.verdict}
              </span>
              <span className="rounded border border-[var(--border-subtle)] bg-[var(--surface)] px-2 py-0.5 text-xs text-[var(--text-secondary)]">
                {selectedSpan.agent}
              </span>
            </div>
            <div>
              <div className="text-[11px] uppercase tracking-wide text-[var(--text-tertiary)]">Finding associations</div>
              {selectedSpan.linked_findings.length > 0 && <p className="mt-1 text-xs text-ink-secondary">Candidate name matches; these do not prove that this span reached the finding.</p>}
              {selectedSpan.linked_findings.length === 0 ? (
                <p className="mt-2 text-xs text-[var(--text-tertiary)]">{selectedSpan.inventory_binding?.inventory_paths?.length ? "No additional finding candidates for this span." : "No verified inventory-to-finding mapping is available for this span."}</p>
              ) : (
                <div className="mt-2 space-y-2">
                  {selectedSpan.linked_findings.map((finding) => (
                    <div key={String(finding.finding_id)} className="rounded-lg border border-[var(--border-subtle)] bg-[var(--background)]/70 p-3">
                      <div className="flex items-center justify-between gap-2">
                        <Link href={`/findings?cve=${encodeURIComponent(String(finding.vulnerability_id || ""))}`} className="font-mono text-xs text-emerald-300 hover:underline">
                          {finding.vulnerability_id}
                        </Link>
                        {finding.effective_reach_band ? (
                          <span className="text-[10px] uppercase text-amber-300">{finding.effective_reach_band}</span>
                        ) : null}
                      </div>
                      {finding.policy_state ? (
                        <div className="mt-1 flex items-center gap-1 text-xs text-rose-300">
                          <AlertTriangle className="h-3 w-3" />
                          Runtime {finding.policy_state}
                        </div>
                      ) : null}
                    </div>
                  ))}
                </div>
              )}
            </div>
            {selectedSpan.compliance_controls.length > 0 && (
              <div>
                <div className="text-[11px] uppercase tracking-wide text-[var(--text-tertiary)]">Compliance controls</div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {selectedSpan.compliance_controls.map((tag) => (
                    <span key={tag} className="rounded border border-[var(--border-subtle)] bg-[var(--surface)] px-2 py-0.5 font-mono text-[10px] text-[var(--text-secondary)]">
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </section>
    </div></>
  );
}


function TraceSpanHistory({ observationId }: { observationId: string }) {
  const [rows, setRows] = useState<Array<{ observed_at: string; verdict: string; metadata: Record<string, unknown> }>>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const [done, setDone] = useState(false);
  const [loaded, setLoaded] = useState(false);
  async function load() {
    setBusy(true); setError(false);
    try {
      const response = await api.getRuntimeObservationRevisions(observationId, rows.length);
      setRows(current => [...current, ...response.observations]);
      setDone(response.count < response.limit); setLoaded(true);
    } catch { setError(true); } finally { setBusy(false); }
  }
  return <details className="border-t border-outline pt-2">
    <summary className="cursor-pointer text-xs">Collection history</summary>
    <p className="my-2 text-xs text-ink-secondary">Retained content revisions in collection order. Collector history is not independent provider evidence.</p>
    <ol className="space-y-2 text-xs">{rows.map((row, index) => <li key={index}>Revision {index + 1}: {row.verdict} · {String(row.metadata.collected_at || row.observed_at)}</li>)}</ol>
    {loaded && rows.length === 0 && <p className="text-xs">No retained revisions.</p>}
    {error && <p role="alert" className="text-xs">History unavailable. Retry to continue from the last loaded revision.</p>}
    {!done && <button type="button" disabled={busy} onClick={() => void load()} className="mt-2 text-xs underline">{busy ? "Loading history…" : loaded ? "Load more revisions" : "Load revisions"}</button>}
  </details>;
}
