"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { Activity, RefreshCw } from "lucide-react";
import { useAuthState } from "@/components/auth-provider";
import { PRODUCER_EVIDENCE_HINT } from "@/lib/gateway-feed";
import { ActivityStreamError, gatewayActivityPage, gatewayFeedSnapshot, mergeActivity, streamGatewayActivity, type GatewayActivity, type ActivityPage } from "@/lib/gateway-activity";


import { ActivityRows } from "./GatewayActivityRows";
import { RuntimeConnectionStatus } from "./RuntimeConnectionStatus";
import { ActivityWindow } from "./GatewayActivityWindow";
import { nowForRelativeTime } from "@/lib/relative-clock";

const messages = {
  connecting: "Connecting to durable activity…",
  live: "Connected to durable activity",
  reconnecting: "Reconnecting from the last complete batch…",
  gap: "Activity gap: retained history moved or the cursor is invalid. The last complete batch is preserved.",
  auth: "Sign in with permission to read gateway activity.",
  unavailable: "Durable activity is unavailable. The last complete batch is preserved.",
  invalid: "Activity response could not be verified. The last complete batch is preserved.",
  snapshot: "Retained feed snapshot, refreshed every 15 seconds. Live streaming needs a signed-in session; this deployment allows anonymous read access.",
};
type StreamState = keyof typeof messages;
const SNAPSHOT_REFRESH_MS = 15_000;

type FeedProps = { onActivity?: (() => void) | undefined; preview?: boolean; initialFilter?: string; initialSearch?: string };

export function GatewayFeedPanel({ onActivity, preview = false, initialFilter = "", initialSearch = "" }: FeedProps) {
  const { session } = useAuthState();
  // The ledger stream refuses anonymous sessions by design; a no-auth deployment still serves the REST feed.
  const anonymousRead = session?.auth_required === false;
  return <ActivityFeed key={`${session?.tenant_id ?? ""}:${session?.subject ?? ""}`} onActivity={onActivity} preview={preview} initialFilter={initialFilter} initialSearch={initialSearch} tenantId={session?.tenant_id ?? undefined} anonymousRead={anonymousRead} />;
}

function ActivityFeed({ onActivity, tenantId, preview, initialFilter, initialSearch, anonymousRead }: FeedProps & { tenantId: string | undefined; anonymousRead: boolean }) {
  const [events, setEvents] = useState<GatewayActivity[]>([]);
  const [state, setState] = useState<StreamState>("connecting");
  const [filter, setFilter] = useState(initialFilter ?? "");
  const [search, setSearch] = useState(initialSearch ?? "");
  const [frozen, setFrozen] = useState<GatewayActivity[] | null>(null);
  const [epoch, setEpoch] = useState(0);
  const [history, setHistory] = useState(false);
  const [latest, setLatest] = useState<number | null>(null);
  const cursor = useRef<string | undefined>(undefined);
  const tenant = useRef<string | undefined>(undefined);
  const rows = useRef<GatewayActivity[]>([]);
  const notify = useRef(onActivity);
  useEffect(() => { notify.current = onActivity; }, [onActivity]);

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let failures = 0;
    let notifiedAt = 0;
    const connect = async () => {
      try {
        for await (const page of streamGatewayActivity(cursor.current, controller.signal, tenantId)) {
          if (controller.signal.aborted) return;
          if (tenant.current && tenant.current !== page.tenant_id) {
            rows.current = []; cursor.current = undefined; setEvents([]);
            setState("auth"); return;
          }
          tenant.current = page.tenant_id;
          rows.current = mergeActivity(rows.current, page.events);
          setEvents(rows.current);
          // Advance only after the entire batch is merged into the local view.
          cursor.current = page.next_cursor;
          setLatest(page.latest_ordinal);
          setState("live");
          failures = 0;
          if (page.events.length && Date.now() - notifiedAt > 3000) {
            notifiedAt = Date.now(); notify.current?.();
          }
        }
      } catch (error) {
        if (controller.signal.aborted) return;
        const kind = error instanceof ActivityStreamError ? error.kind : "transport";
        if (kind === "auth" && anonymousRead) { await snapshot(); return; }
        if (kind !== "transport") { setState(kind); return; }
        failures += 1;
        if (failures > 5) { setState("unavailable"); return; }
      }
      if (!controller.signal.aborted) {
        setState("reconnecting");
        timer = setTimeout(() => void connect(), Math.min(1000 * 2 ** failures, 30000));
      }
    };
    // Anonymous read-only sessions poll the REST feed the API does serve them.
    const snapshot = async () => {
      try {
        const page = await gatewayFeedSnapshot(controller.signal);
        if (controller.signal.aborted) return;
        tenant.current = page.tenant_id;
        rows.current = mergeActivity(rows.current, page.events);
        setEvents(rows.current);
        setLatest(page.latest_ordinal);
        setState("snapshot");
        if (page.events.length && nowForRelativeTime() - notifiedAt > 3000) { notifiedAt = nowForRelativeTime(); notify.current?.(); }
      } catch (error) {
        if (controller.signal.aborted) return;
        const kind = error instanceof ActivityStreamError ? error.kind : "transport";
        setState(kind === "auth" ? "unavailable" : kind === "transport" ? "reconnecting" : kind);
      }
      if (!controller.signal.aborted) timer = setTimeout(() => void snapshot(), SNAPSHOT_REFRESH_MS);
    };
    const start = setTimeout(() => void connect(), 0);
    return () => { clearTimeout(start); clearTimeout(timer); controller.abort(); };
  }, [epoch, tenantId, anonymousRead]);

  const reconnect = (restart = false) => {
    if (restart) { cursor.current = undefined; rows.current = []; tenant.current = undefined; setEvents([]); setLatest(null); setFrozen(null); }
    setState("connecting"); setEpoch(value => value + 1);
  };
  const receiptTime = events[0]?.ingested_at;
  const staleReceipt = Boolean(receiptTime && nowForRelativeTime() - Date.parse(receiptTime) > 120000);
  const displayed = frozen ?? events;
  const visible = displayed.filter(row => (!filter || (filter === "deny" ? row.decision === "deny" : filter === "data" ? /dlp|visual/.test(row.event_type) : row.event_type.includes(filter))) &&
    [row.agent_id, row.tool, row.upstream, row.reason_code, row.profile_id, row.identity_id, row.source_id, row.session_id, row.submission_provenance?.reported_source_id, row.submission_provenance?.reported_session_id].join(" ").toLowerCase().includes(search.toLowerCase()));
  const params = new URLSearchParams();
  if (filter) params.set("filter", filter);
  if (search) params.set("q", search);
  const activityHref = `/live-activity${params.size ? `?${params}` : ""}`;
  const scope = (nextFilter: string, nextSearch: string) => {
    setFilter(nextFilter); setSearch(nextSearch);
    if (!preview && window.location.pathname === "/live-activity") {
      const query = new URLSearchParams();
      if (nextFilter) query.set("filter", nextFilter);
      if (nextSearch) query.set("q", nextSearch);
      window.history.replaceState(null, "", `/live-activity${query.size ? `?${query}` : ""}`);
    }
  };
  const pending = frozen ? events.filter(row => row.ingest_ordinal > (frozen[0]?.ingest_ordinal ?? 0)).length : 0;

  return <section className="min-w-0 rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] p-4 sm:p-5" aria-label="Gateway activity">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h3 className="flex items-center gap-2 text-sm font-semibold"><Activity className="h-4 w-4" />Gateway activity</h3>
        <p className="mt-1 text-xs text-[var(--text-secondary)]">Canonical tool calls, data filters, profile and enforcement decisions.</p>
        <p className="mt-1 text-xs text-[var(--text-secondary)]" role="status">{messages[state]}</p>
      </div>
      <div className="flex flex-wrap gap-2">
        {preview ? <Link className="graph-page-action" href={activityHref}>Open live activity</Link> : <button className="graph-page-action" onClick={() => setFrozen(value => value ? null : events)}>{frozen ? `Resume · ${pending} new in buffer` : "Pause view"}</button>}
        {!preview && !anonymousRead && <button className="graph-page-action" onClick={() => setHistory(value => !value)}>{history ? "Return to recent activity" : "Browse retained history"}</button>}
        {state === "gap" ? <button className="graph-page-action" onClick={() => reconnect(true)}>Start a new retained window</button> :
          <button className="graph-page-action" onClick={() => reconnect()}><RefreshCw className="h-3 w-3" />Reconnect</button>}
      </div>
    </div>
    <p className="my-3 text-xs text-[var(--text-tertiary)]">{preview ? `Showing ${Math.min(5, visible.length)} recent matches` : `Newest ${displayed.length} events in this view`} · bounded to 1,000 received events, not a complete history.</p>
    {!preview && <RuntimeConnectionStatus tenantId={tenantId} streamState={state} events={events} onBlocked={() => scope("deny", "")} />}
    {!preview && <div className="my-3 flex flex-wrap gap-4" aria-label="Activity window summary">
      {[["Blocked", displayed.filter(row => row.decision === "deny").length], ["Warnings", displayed.filter(row => /warned|dev_bypass/.test(row.event_type)).length], ["Without trace ID", displayed.filter(row => !row.trace_id).length]].map(([label, count]) =>
        <div key={label} className="flex items-baseline gap-2"><p className="text-xs text-[var(--text-secondary)]">{label}</p><p className="text-sm font-semibold">{displayed.length ? count : "—"}</p></div>)}
    </div>}
    {staleReceipt && <p className="mb-3 text-xs text-amber-800 dark:text-amber-200">Latest receipt is older than 2 minutes. A connected transport does not prove current producer activity.</p>}
    {history ? <RetainedHistory tenantId={tenant.current ?? tenantId} /> : <>
      <div className="mb-3 flex flex-wrap gap-2" aria-label="Activity filters">
        {[["", "All"], ["deny", "Blocked"], ["data", "Data filters"], ["runtime_profile", "Profile decisions"], ["enforcement", "Enforcement"]].map(([value, label]) =>
          <button key={label} onClick={() => scope(value ?? "", search)} aria-pressed={filter === value} className={`rounded px-2 py-1 text-xs ${filter === value ? "bg-[var(--surface-muted)] text-[var(--foreground)]" : "text-[var(--text-secondary)]"}`}>{label}</button>)}
      </div>
      <label className="mb-3 block text-xs text-[var(--text-secondary)]">Search agent, origin, profile, tool or reason
        <input value={search} onChange={event => scope(filter, event.target.value)} className="mt-1 block w-full rounded-lg border border-[var(--border-subtle)] bg-[var(--background)] px-3 py-2 text-sm text-[var(--foreground)]" placeholder="Filter activity…" />
      </label>
      {!visible.length && <p className="py-6 text-sm text-[var(--text-secondary)]">{events.length ? "No activity matches this filter." : state === "live" || state === "snapshot" ? "No retained gateway activity yet." : "No verified activity loaded."}</p>}
      {preview ? <ActivityRows events={visible.slice(0, 5)} /> : <ActivityWindow key={`${filter}:${search}`} events={visible} onFreeze={() => setFrozen(value => value ?? events)} />}
    </>}
    {!preview && <details className="mt-4 text-xs text-[var(--text-secondary)]"><summary className="cursor-pointer">Stream and evidence details</summary><p className="mt-2">Ledger position {latest ?? "unavailable"}. Pausing freezes the view, not collection. History is paged separately; reconnects resume the last complete batch. {PRODUCER_EVIDENCE_HINT}</p></details>}
  </section>;
}

function RetainedHistory({ tenantId }: { tenantId: string | undefined }) {
  const [page, setPage] = useState<ActivityPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [epoch, setEpoch] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    void gatewayActivityPage(cursor, controller.signal, tenantId).then(result => {
      if (!controller.signal.aborted) { setPage(result); setError(null); setLoading(false); }
    }).catch(caught => {
      if (controller.signal.aborted) return;
      setError(caught instanceof ActivityStreamError && caught.kind === "gap" ? "History expired. Choose Restart history to read the currently retained window." : "Retained history is unavailable. Retry without advancing the page.");
      setLoading(false);
    });
    return () => controller.abort();
  }, [cursor, epoch, tenantId]);
  return <div>
    <div className="mb-3 flex flex-wrap items-center gap-3">
      <span className="text-xs text-[var(--text-secondary)]">Retained history · oldest pages first</span>
      <button className="graph-page-action" disabled={loading} onClick={() => { setLoading(true); setCursor(undefined); setEpoch(n => n + 1); }}>Restart history</button>
      {error ? <button className="graph-page-action" onClick={() => { setLoading(true); setEpoch(n => n + 1); }}>Retry history</button> : null}
      <button className="graph-page-action" disabled={loading || !page?.has_more || Boolean(error)} onClick={() => { setLoading(true); setCursor(page?.next_cursor); }}>Next retained page</button>
    </div>
    {loading ? <p role="status">Loading retained page…</p> : null}
    {error ? <p role="alert" className="text-sm text-amber-800 dark:text-amber-200">{error}</p> : null}
    {page && <ActivityRows events={[...page.events].reverse()} />}
  </div>;
}
