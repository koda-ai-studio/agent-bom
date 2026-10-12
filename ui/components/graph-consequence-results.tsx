"use client";
import { useEffect, useRef, useState } from "react";
import { ArrowLeft, Download, Route, ShieldCheck } from "lucide-react";
import type { GraphConsequenceResponse } from "@/lib/api-types";
import { GraphPrerequisiteChecks } from "@/components/graph-prerequisite-checks";
import { GraphConsequencePath, actionLabels, consequenceTitle, readable, statusLabels, targetLabel } from "@/components/graph-consequence-path";

export function GraphConsequenceResults({ result }: { result: GraphConsequenceResponse }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [selected, setSelected] = useState(result.consequences[0]?.id);
  const item = result.consequences.find(candidate => candidate.id === selected) ?? result.consequences[0];
  function open() { const el = dialog.current; if (el && !el.open) { if (el.showModal) el.showModal(); else el.setAttribute("open", ""); } }
  useEffect(() => { open(); }, []);
  function download() {
    const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = "graph-consequences.json"; link.click(); URL.revokeObjectURL(url);
  }
  return <>
    <button type="button" onClick={open} className="rounded-lg bg-teal-700 px-4 py-2 font-medium text-white">Open consequence investigation</button>
    <dialog ref={dialog} aria-label="Consequence investigation" className="fixed inset-0 m-auto h-[96dvh] max-h-none w-[min(1440px,96vw)] max-w-none overflow-y-auto rounded-2xl border border-outline bg-background p-0 text-foreground shadow-2xl backdrop:bg-black/55">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-outline bg-surface px-5 py-4 sm:px-8">
        <button autoFocus type="button" onClick={() => dialog.current?.close()} className="inline-flex items-center gap-2 text-sm font-medium"><ArrowLeft className="h-4 w-4" />Back to inventory</button>
        <span className="text-xs text-ink-secondary">Read-only assessment · experimental</span>
        <button type="button" onClick={download} className="inline-flex items-center gap-2 rounded-lg border border-outline px-3 py-2 text-xs"><Download className="h-4 w-4" />Export consequences JSON</button>
      </header>
      <div className="space-y-6 p-5 sm:p-8">
        <div>
          <p className="mb-2 text-xs font-medium uppercase tracking-widest text-teal-700 dark:text-teal-300">Consequence investigation</p>
          <h2 className="text-2xl font-semibold tracking-tight sm:text-3xl">{item ? consequenceTitle(item) : "What is needed to establish impact?"}</h2>
          <p className="mt-2 max-w-3xl text-sm text-ink-secondary">{result.request?.mode === "vulnerability" ? "Check the affected component before tracing downstream authority." : "If this agent or principal were controlled, these are the actions supported or stopped by the collected evidence."}</p>
        </div>
        <dl className="grid grid-cols-2 gap-3 lg:grid-cols-4">{(["supported", "conditional", "blocked", "unknown"] as const).map(status => <div key={status} className="rounded-xl border border-outline bg-surface px-4 py-3"><dt className="text-xs text-ink-secondary">{statusLabels[status]}</dt><dd className="mt-1 text-2xl font-semibold">{result.counts[status]}</dd></div>)}</dl>
        {result.truncated && <p role="status" className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm">Partial assessment. Counts are lower bounds; no absence of exposure can be inferred.</p>}
        <div className="grid items-start gap-5 lg:grid-cols-[250px_minmax(0,1fr)]">
          <aside aria-label="Consequence actions" className="order-2 space-y-2 lg:order-none">
            <h3 className="mb-3 text-sm font-semibold">Actions &amp; affected resources</h3>
            {result.consequences.map(candidate => <button type="button" key={candidate.id} aria-pressed={item?.id === candidate.id} onClick={() => setSelected(candidate.id)} className={`w-full rounded-xl border p-4 text-left transition ${item?.id === candidate.id ? "border-teal-600 bg-teal-500/10 ring-1 ring-teal-600" : "border-outline bg-surface hover:border-outline-strong"}`}>
              <span className="block text-sm font-semibold">{actionLabels[candidate.category] ?? readable(candidate.category)}</span><span className="mt-1 block break-words text-xs text-ink-secondary">{targetLabel(candidate)}</span>
              <span className={`mt-3 inline-flex items-center gap-1 text-xs ${candidate.status === "blocked" ? "text-rose-700 dark:text-rose-300" : "text-ink-secondary"}`}>{candidate.status === "blocked" ? <ShieldCheck className="h-3 w-3" /> : <Route className="h-3 w-3" />}{statusLabels[candidate.status]}</span>
            </button>)}
          </aside>
          <div className="min-w-0 space-y-4">
            <GraphPrerequisiteChecks checks={result.prerequisites.checks ?? []} />
            {item ? <GraphConsequencePath item={item} /> : <div className="rounded-xl border border-outline bg-surface p-6"><p className="font-medium">No qualified action consequences returned.</p><p className="mt-2 text-sm text-ink-secondary">This does not establish safety. The missing prerequisites below identify what to collect next.</p></div>}
            {item && <details className="rounded-xl border border-outline bg-surface p-4 text-xs text-ink-secondary"><summary className="cursor-pointer text-sm font-medium text-foreground">Inspect receipt details</summary>
              <dl className="mt-4 space-y-3 break-all">
                <div><dt className="font-semibold">Node identities</dt><dd>{item.node_ids.join(" → ")}</dd></div>
                <div><dt className="font-semibold">Edge receipts</dt><dd>{item.edge_ids.join(" → ") || "Recorded decision boundary; no access edge"}</dd></div>
                <div><dt className="font-semibold">Bindings</dt><dd>{[...item.binding_ids, ...(item.deny_binding_ids ?? [])].join(", ") || "Not recorded"}</dd></div>
                <div><dt className="font-semibold">Sessions</dt><dd>{item.session_ids.join(", ") || "Root assumption only"}</dd></div>
                <div><dt className="font-semibold">Observed</dt><dd>{item.observed_at ?? "Unknown"}</dd></div>
                <div><dt className="font-semibold">Reasons</dt><dd>{item.reason_codes.map(readable).join("; ") || "No additional qualifiers"}</dd></div>
              </dl>
            </details>}
            <section className="rounded-xl border border-outline bg-surface p-5">
              <h3 className="text-sm font-semibold">What still needs evidence</h3>
              {(result.prerequisites.reason_codes ?? []).length > 0 && <p className="mt-3 text-sm">Prerequisites: {(result.prerequisites.reason_codes ?? []).map(readable).join("; ")}</p>}
              <ul className="mt-3 space-y-3 text-sm text-ink-secondary">{result.frontier.slice(0, 10).map((entry, index) => <li key={index}><p className="font-medium text-foreground">{entry.reason_codes.map(readable).join("; ")}</p><p className="mt-1">{entry.next_collection_step}</p></li>)}</ul>
              {result.frontier.length > 10 && <p className="mt-3 text-xs">Export includes all {result.frontier.length} evidence boundaries.</p>}
              <p className="mt-3 text-xs text-ink-secondary">Estate coverage is unknown. Current access and observed effects are not established. Counts group actions and targets; the queue preserves separate paths.</p>
            </section>
          </div>
        </div>
        <footer className="break-all border-t border-outline pt-4 text-xs text-ink-tertiary">Snapshot {result.scan_id} · revision {result.snapshot_generation} · assessed {result.assessed_at}</footer>
      </div>
    </dialog>
  </>;
}
