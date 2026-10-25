"use client";

import { useEffect, useState, type FormEvent } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { ChevronLeft, ChevronRight, RefreshCw, SearchX } from "lucide-react";

import { PageEmptyState, PageErrorState, PageLoadingState } from "@/components/states/page-state";
import {
  AFFECTED_PAGE_LIMIT,
  classifyAffectedFailure,
  getAdvisoryAffected,
  isAffectedVerdictFilter,
  type AdvisoryAffectedResponse,
  type AffectedLoadFailure,
  type AffectedVerdictFilter,
} from "@/lib/advisory-affected";

import { AffectedAssetsTable } from "./affected-assets-table";
import { AffectedFilterToolbar } from "./affected-filter-toolbar";
import { AdvisoryHeader, AffectedNotices, AffectedSummaryTiles } from "./affected-summary";
import { Field, inputClass, primaryButtonClass, secondaryButtonClass } from "./advisory-form-fields";

type LoadState = { status: "loading" } | { status: "ready"; data: AdvisoryAffectedResponse } | { status: "failed"; failure: AffectedLoadFailure };

const MAX_AUTO_RETRY_SECONDS = 120;

function AdvisoryPicker({ onPick }: { onPick: (id: string) => void }) {
  const [value, setValue] = useState("");
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (value.trim()) onPick(value.trim());
  };
  return (
    <form onSubmit={submit} className="max-w-xl space-y-3 rounded-xl border border-outline bg-surface p-4">
      <p className="text-sm text-ink-secondary">Answer &ldquo;am I affected?&rdquo; for one advisory from stored inventory, per asset. Use a CVE, GHSA or an emergency advisory id.</p>
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
        <Field id="affected-advisory-id" label="Advisory ID" className="flex-1">
          {props => <input {...props} className={inputClass} value={value} onChange={e => setValue(e.target.value)} placeholder="CVE-2026-12345" autoComplete="off" />}
        </Field>
        <button type="submit" className={primaryButtonClass}>Show affected assets</button>
      </div>
    </form>
  );
}

function FailureState({ failure, advisoryId, onFirstPage, onRetry }: { failure: AffectedLoadFailure; advisoryId: string; onFirstPage: () => void; onRetry: () => void }) {
  switch (failure.kind) {
    case "snapshot_changed":
      return (
        <div role="alert" className="flex flex-col gap-3 rounded-xl border border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] p-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-sm font-medium text-foreground">Results changed — reload from first page</p>
            <p className="mt-0.5 text-xs text-ink-secondary">A scan or advisory update landed after this page was read, so the next page would mix two snapshots.</p>
          </div>
          <button type="button" className={primaryButtonClass} onClick={onFirstPage}><RefreshCw className="h-4 w-4" aria-hidden />Reload from first page</button>
        </div>
      );
    case "not_found":
      return <PageEmptyState compact icon={SearchX} title="Advisory not found" detail={`No emergency advisory or feed record matches ${advisoryId}. Declare it as an emergency advisory to match it against stored scans.`} action={{ label: "Declare an emergency advisory", href: "/advisories?tab=declare" }} />;
    case "seeding":
      return <PageEmptyState compact title="Control plane is still loading inventory" detail={failure.retryAfterSeconds ? `Retry in about ${failure.retryAfterSeconds} seconds.` : "Retry shortly."} action={{ label: "Retry now", onClick: onRetry }} />;
    case "invalid":
      return <PageErrorState compact title="The request was rejected" detail={failure.message} action={{ label: "Reload from first page", onClick: onFirstPage }} />;
    default:
      return <PageErrorState compact title="Affected assets unavailable" detail={failure.message} action={{ label: "Retry", onClick: onRetry }} />;
  }
}

function PageControls({ page, data, onPrevious, onNext }: { page: number; data: AdvisoryAffectedResponse; onPrevious: () => void; onNext: () => void }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <p className="text-xs text-ink-tertiary">Page {page} · {data.count.toLocaleString()} {data.count === 1 ? "row" : "rows"}{data.has_more ? " · more on the next page" : ""}</p>
      <div className="flex items-center gap-1">
        <button type="button" className={secondaryButtonClass} disabled={page <= 1} onClick={onPrevious}><ChevronLeft className="h-3 w-3" aria-hidden />Prev</button>
        <button type="button" className={secondaryButtonClass} disabled={!data.has_more || !data.next_cursor} onClick={onNext}>Next<ChevronRight className="h-3 w-3" aria-hidden /></button>
      </div>
    </div>
  );
}

/** Cursor pages for one advisory + filter set; remounted (keyed) whenever the filters change. */
function AffectedResults({ advisoryId, verdict, q, onVerdict, onSearch }: {
  advisoryId: string;
  verdict: AffectedVerdictFilter;
  q: string;
  onVerdict: (next: AffectedVerdictFilter) => void;
  onSearch: (next: string) => void;
}) {
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const [reloadKey, setReloadKey] = useState(0);
  const [state, setState] = useState<LoadState>({ status: "loading" });
  const [lastGood, setLastGood] = useState<AdvisoryAffectedResponse | null>(null);
  const cursor = cursors[cursors.length - 1] ?? null;

  useEffect(() => {
    const controller = new AbortController();
    setState({ status: "loading" });
    getAdvisoryAffected(advisoryId, { verdict, q, cursor, limit: AFFECTED_PAGE_LIMIT }, controller.signal)
      .then(data => {
        if (controller.signal.aborted) return;
        setState({ status: "ready", data });
        setLastGood(data);
      })
      .catch(error => {
        if (!controller.signal.aborted) setState({ status: "failed", failure: classifyAffectedFailure(error) });
      });
    return () => controller.abort();
  }, [advisoryId, verdict, q, cursor, reloadKey]);

  const retryAfter = state.status === "failed" && state.failure.kind === "seeding" ? state.failure.retryAfterSeconds : null;
  useEffect(() => {
    if (!retryAfter || retryAfter > MAX_AUTO_RETRY_SECONDS) return;
    const timer = window.setTimeout(() => setReloadKey(key => key + 1), retryAfter * 1000);
    return () => window.clearTimeout(timer);
  }, [retryAfter]);

  const firstPage = () => { setCursors([null]); setReloadKey(key => key + 1); };
  const header = state.status === "ready" ? state.data : lastGood;

  return (
    <div className="min-w-0 space-y-4">
      {header ? <AdvisoryHeader advisory={header.advisory} /> : null}
      {header ? <AffectedSummaryTiles answer={header} /> : null}
      {state.status === "ready" ? <AffectedNotices answer={state.data} /> : null}
      <AffectedFilterToolbar verdict={verdict} q={q} summary={header?.summary ?? null} onVerdict={onVerdict} onSearch={onSearch} />
      {state.status === "loading" ? <PageLoadingState compact title="Matching stored inventory" detail={`Reading affected assets for ${advisoryId}.`} /> : null}
      {state.status === "failed" ? <FailureState failure={state.failure} advisoryId={advisoryId} onFirstPage={firstPage} onRetry={() => setReloadKey(key => key + 1)} /> : null}
      {state.status === "ready" ? (
        state.data.rows.length ? (
          <>
            <AffectedAssetsTable rows={state.data.rows} />
            <PageControls page={cursors.length} data={state.data}
              onPrevious={() => setCursors(stack => (stack.length > 1 ? stack.slice(0, -1) : stack))}
              onNext={() => { const next = state.data.next_cursor; if (next) setCursors(stack => [...stack, next]); }} />
          </>
        ) : (
          <p className="rounded-xl border border-outline bg-surface-muted px-3 py-6 text-center text-sm text-ink-secondary">
            {verdict !== "all" || q ? "No assets match these filters." : "No asset in stored inventory carries a package this advisory names."}
          </p>
        )
      ) : null}
    </div>
  );
}

/** "Am I affected by this advisory?" per asset, URL-synced (`?id=&verdict=&q=`). */
export function AdvisoryAffectedView() {
  const router = useRouter();
  const pathname = usePathname() || "/advisories";
  const searchParams = useSearchParams();
  const advisoryId = searchParams.get("id")?.trim() ?? "";
  const rawVerdict = searchParams.get("verdict");
  const verdict: AffectedVerdictFilter = isAffectedVerdictFilter(rawVerdict) ? rawVerdict : "all";
  const q = searchParams.get("q")?.trim() ?? "";

  const navigate = (next: { id: string; verdict?: AffectedVerdictFilter; q?: string }) => {
    const params = new URLSearchParams();
    params.set("id", next.id);
    if (next.verdict && next.verdict !== "all") params.set("verdict", next.verdict);
    if (next.q) params.set("q", next.q);
    router.replace(`${pathname}?${params.toString()}`, { scroll: false });
  };

  if (!advisoryId) return <AdvisoryPicker onPick={id => navigate({ id })} />;
  return (
    <AffectedResults
      key={`${advisoryId}|${verdict}|${q}`}
      advisoryId={advisoryId}
      verdict={verdict}
      q={q}
      onVerdict={next => navigate({ id: advisoryId, verdict: next, q })}
      onSearch={next => navigate({ id: advisoryId, verdict, q: next })}
    />
  );
}
