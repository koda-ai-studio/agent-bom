"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { PageLoadingState } from "@/components/states/page-loading-state";
import { getAffected, REACH_LABEL, VERDICT_LABEL, type AffectedAnswer } from "@/lib/incident-exposure";

const TONE: Record<AffectedAnswer["verdict"], string> = {
  affected: "border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] text-[color:var(--status-danger)]",
  possibly_affected: "border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] text-[color:var(--status-warn)]",
  previously_affected: "border-outline bg-surface text-ink-secondary",
  not_found: "border-[color:var(--status-success-border)] bg-[color:var(--status-success-bg)] text-[color:var(--status-success)]",
};

function day(value: string | null | undefined): string {
  return value ? value.slice(0, 10) : "unknown";
}

function Exposure({ answer }: { answer: AffectedAnswer }) {
  const { findings, exposure, reach } = answer;
  const kinds = Object.entries(reach.by_kind).filter(([, count]) => count > 0);
  return (
    <dl className="grid gap-3 text-sm sm:grid-cols-3">
      <div>
        <dt className="text-xs text-ink-tertiary">Exposure window</dt>
        <dd className="font-medium text-foreground">{day(exposure.first_seen)} → {exposure.still_open ? "now" : day(exposure.last_resolved_at ?? exposure.last_seen)}</dd>
      </div>
      <div>
        <dt className="text-xs text-ink-tertiary">Findings</dt>
        <dd className="font-medium text-foreground">
          {findings.open} open · {findings.resolved} resolved{findings.kev ? " · KEV" : ""} · {findings.fix_available} with a fix, {findings.no_fix} without
        </dd>
      </div>
      <div>
        <dt className="text-xs text-ink-tertiary">Reaches{reach.scan_id ? ` (graph snapshot ${reach.scan_id})` : ""}</dt>
        <dd className="font-medium text-foreground" data-testid="exposure-reach">
          {kinds.length ? kinds.map(([kind, count]) => `${count} ${REACH_LABEL[kind] ?? kind}`).join(" · ") : "No recorded reach"}
        </dd>
      </div>
    </dl>
  );
}

/** A body the panel can draw; anything else (an older control plane, a proxy page) reads as unavailable. */
function isAnswer(value: unknown): value is AffectedAnswer {
  const answer = value as Partial<AffectedAnswer> | null;
  return Boolean(answer && typeof answer === "object" && answer.verdict && answer.verdict in VERDICT_LABEL
    && answer.findings && answer.exposure && answer.reach?.by_kind && Array.isArray(answer.verdict_basis));
}

/** The incident answer for one advisory or package: verdict, how long, what it reaches. */
export function ExposurePanel({ query }: { query: string }) {
  const [state, setState] = useState<{ status: "loading" } | { status: "ready"; answer: AffectedAnswer } | { status: "failed" }>({ status: "loading" });
  useEffect(() => {
    const controller = new AbortController();
    setState({ status: "loading" });
    getAffected(query, controller.signal).then(answer => setState(isAnswer(answer) ? { status: "ready", answer } : { status: "failed" }), () => {
      if (!controller.signal.aborted) setState({ status: "failed" });
    });
    return () => controller.abort();
  }, [query]);
  if (state.status === "loading") return <PageLoadingState compact title="Checking exposure" detail={`Reading findings and reach for ${query}.`} />;
  if (state.status === "failed") return <p role="status" className="text-sm text-ink-secondary">Exposure for {query} is unavailable right now.</p>;
  const { answer } = state;
  return (
    <section aria-label={`Exposure to ${query}`} data-testid="exposure-panel" className="space-y-3 rounded-xl border border-outline bg-surface p-4">
      <div className="flex flex-wrap items-center gap-3">
        <span data-verdict={answer.verdict} className={`rounded-full border px-3 py-1 text-sm font-semibold ${TONE[answer.verdict]}`}>{VERDICT_LABEL[answer.verdict]}</span>
        <span className="text-sm text-ink-secondary">
          {answer.verdict_basis.length ? `From ${answer.verdict_basis.map(basis => basis === "findings" ? "scan findings" : "inventory version ranges").join(" and ")}` : "No finding or inventory match"}
        </span>
        {answer.findings.total > 0 && <Link href={answer.findings_href} className="ml-auto text-sm font-medium text-[color:var(--accent)] underline">View {answer.findings.total} findings</Link>}
      </div>
      {answer.verdict !== "not_found" && <Exposure answer={answer} />}
      {answer.reach.note && <p className="text-xs text-ink-tertiary">{answer.reach.note}</p>}
    </section>
  );
}
