"use client";

import Link from "next/link";
import { TraceConnectorsPanel } from "@/components/trace-connectors-panel";
import { useExperimentalFeature, type ExperimentalState } from "@/lib/experimental";

const EXPERIMENTAL_DOC = "https://github.com/koda-ai-studio/agent-bom/blob/main/docs/EXPERIMENTAL.md";

function ExperimentalBadge() {
  return <span className="ml-2 rounded-full border border-amber-500/50 bg-amber-500/10 px-2 py-0.5 text-[11px] font-medium text-amber-800 dark:text-amber-300">Experimental</span>;
}

function TracePullSection({ state }: { state: ExperimentalState }) {
  if (state.status === "loading") return <p className="text-sm text-[var(--text-secondary)]">Checking whether trace pull is enabled…</p>;
  if (state.status === "disabled") {
    return <section aria-label="Trace pull disabled" className="rounded-xl border border-amber-500/40 bg-amber-500/5 p-4 text-sm">
      <h3 className="font-medium">Trace pull is experimental and disabled on this server</h3>
      <p className="mt-1 text-[var(--text-secondary)]">An operator can enable it with <code>{state.feature.enabled_by}</code> on the control plane, then reload this page.</p>
      <a href={EXPERIMENTAL_DOC} target="_blank" rel="noopener noreferrer" className="mt-2 inline-block underline">About experimental features</a>
    </section>;
  }
  return <TraceConnectorsPanel />;
}

export function ObservabilityConnections() {
  const traces = useExperimentalFeature("traces");
  return <div className="space-y-5">
    <div>
      <h2 className="text-xl font-semibold">Observability &amp; SIEM</h2>
      <p className="mt-1 max-w-3xl text-sm text-[var(--text-secondary)]">Bring trace evidence into Agent-Bom, or configure where security events go. Traces link execution steps; logs and events remain individual records that can reference those traces.</p>
    </div>
    <nav aria-label="Telemetry connection workflows" className="grid gap-3 md:grid-cols-3">
      <div aria-current="page" className="rounded-xl border border-emerald-600/50 bg-emerald-500/5 p-4">
        <p className="text-xs text-[var(--text-secondary)]">Inbound · pull</p><h3 className="mt-1 font-medium">Platform traces<ExperimentalBadge /></h3><p className="mt-1 text-sm text-[var(--text-secondary)]">Langfuse and LangSmith tool-call samples, correlated with tenant findings.</p>
      </div>
      <Link href="/traces?view=ingest" className="rounded-xl border border-[var(--border-subtle)] p-4 hover:bg-[var(--surface-muted)]">
        <p className="text-xs text-[var(--text-secondary)]">Inbound · push</p><h3 className="mt-1 font-medium">Receive OTLP traces</h3><p className="mt-1 text-sm text-[var(--text-secondary)]">Review a collector export and its trace ingestion contract.</p>
      </Link>
      <Link href="/integrations?tab=siem" className="rounded-xl border border-[var(--border-subtle)] p-4 hover:bg-[var(--surface-muted)]">
        <p className="text-xs text-[var(--text-secondary)]">Outbound · security events</p><h3 className="mt-1 font-medium">SIEM destinations</h3><p className="mt-1 text-sm text-[var(--text-secondary)]">Open the existing connector and event-format tests.</p>
      </Link>
    </nav>
    <TracePullSection state={traces} />
  </div>;
}
