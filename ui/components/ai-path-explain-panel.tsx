"use client";

import { useState } from "react";
import { Loader2, Sparkles } from "lucide-react";

import { explainGraphSelection, type GraphExplanation } from "@/lib/api-ai-advice";

function errorText(error: unknown): string {
  if (error && typeof error === "object") {
    const record = error as { message?: unknown; detail?: unknown };
    if (typeof record.message === "string" && record.message) return record.message;
    const detail = record.detail as { reason?: unknown } | string | undefined;
    if (typeof detail === "string") return detail;
    if (detail && typeof detail.reason === "string") return detail.reason;
  }
  return "The explanation could not be generated. Graph evidence is unaffected.";
}

/** Asks a model about one recorded path. Citations and limits come back with the claims, shown as text only. */
export function AIPathExplainPanel({ nodeIds, scanId }: { nodeIds: string[]; scanId?: string | undefined }) {
  const [state, setState] = useState<{ status: "idle" | "loading" } | { status: "error"; message: string } | { status: "done"; result: GraphExplanation }>({ status: "idle" });

  const explain = () => {
    setState({ status: "loading" });
    explainGraphSelection({ nodeIds, ordered: true, scanId }).then(
      (result) => setState({ status: "done", result }),
      (error: unknown) => setState({ status: "error", message: errorText(error) }),
    );
  };

  const removed = state.status === "done" ? Object.values(state.result.rejected_claims).reduce((sum, count) => sum + count, 0) : 0;
  return (
    <div className="space-y-2">
      <button
        type="button"
        onClick={explain}
        disabled={state.status === "loading" || nodeIds.length === 0}
        className="inline-flex items-center gap-1.5 rounded-lg border border-outline px-3 py-1.5 text-xs text-foreground hover:bg-surface disabled:opacity-60"
      >
        {state.status === "loading" ? <Loader2 aria-hidden="true" className="h-3.5 w-3.5 animate-spin" /> : <Sparkles aria-hidden="true" className="h-3.5 w-3.5" />}
        Explain this path
      </button>
      {state.status === "error" ? <p role="alert" className="break-words text-xs text-ink-secondary">{state.message}</p> : null}
      {state.status === "done" ? (
        <section aria-label="Path explanation, AI advice" className="space-y-3 rounded-lg border border-dashed border-outline bg-surface-muted p-3">
          <h4 className="text-xs font-medium uppercase tracking-wide text-ink-secondary">AI advice</h4>
          {state.result.claims.length === 0 ? <p className="text-sm text-ink-secondary">No claim could be tied to recorded graph evidence, so none is shown.</p> : null}
          <ol className="space-y-2">
            {state.result.claims.map((claim, index) => (
              <li key={`${index}-${claim.text}`} className="text-sm text-foreground">
                <p className="max-w-prose break-words leading-6">{claim.text}</p>
                {claim.note ? <p className="mt-0.5 text-xs italic text-ink-tertiary">Model note, not evidence: {claim.note}</p> : null}
                <ul aria-label="Citations" className="mt-1 flex flex-wrap gap-1">
                  {claim.citations.map((citation) => (
                    <li key={citation.ref} title={citation.id} className="max-w-full break-all rounded border border-outline px-1.5 py-0.5 font-mono text-[11px] text-ink-secondary">
                      {citation.kind}: {citation.label} ({citation.id}){citation.traversable === false ? ", not traversable" : ""}
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ol>
          <div>
            <p className="text-xs font-medium text-ink-secondary">What the graph does not show</p>
            <ul className="mt-1 list-disc space-y-1 pl-4 text-xs text-ink-secondary">
              {state.result.evidence_limits.map((limit) => <li key={limit} className="break-words">{limit}</li>)}
            </ul>
          </div>
          {removed > 0 ? <p className="text-xs text-ink-tertiary">{removed === 1 ? "1 claim was" : `${removed} claims were`} removed or corrected because they cited nothing real or disagreed with the recorded edge.</p> : null}
          <p className="break-words text-xs text-ink-tertiary">{[state.result.provenance.model, state.result.provenance.generated_at.slice(0, 10), state.result.provenance.prompt_version].join(" · ")}. The server wrote each sentence from the recorded edge; the model only chose what to show. It adds nothing to the graph.</p>
        </section>
      ) : null}
    </div>
  );
}
