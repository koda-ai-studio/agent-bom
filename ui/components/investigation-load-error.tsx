import Link from "next/link";
import { ArrowRight, GitBranch } from "lucide-react";

import { BusyRetryCountdown } from "@/components/busy-retry-countdown";
import { GraphEmptyState } from "@/components/graph-state-panels";
import type { QueueStateCopy } from "@/lib/investigation-queue-copy";

/** The attack-path queue could not load: say so, and offer the full graph and a focus reset. */
export function InvestigationLoadError({ copy, retryHref, resetFocusHref, busy = false, onRetry }: {
  copy: QueueStateCopy; retryHref: string; resetFocusHref: string | null; busy?: boolean; onRetry?: () => void;
}) {
  if (busy) {
    return (
      <section className="rounded-3xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
        <GraphEmptyState
          title="The API is busy — attack paths will load shortly"
          detail="The server is running but is shedding graph reads under load. This is temporary; the queue retries on its own."
          suggestions={["Keep this page open; it reloads the queue when the API has capacity."]}
        />
        {onRetry ? <BusyRetryCountdown onRetry={onRetry} /> : null}
      </section>
    );
  }
  return (
    <section className="rounded-3xl border border-[color:var(--severity-critical-border)] bg-[color:var(--severity-critical-bg)] p-4">
      <GraphEmptyState title={copy.title} detail={copy.detail} suggestions={copy.suggestions} />
      <div className="mt-4 flex flex-wrap gap-3 border-t border-red-900/40 pt-4">
        <Link href={retryHref} className="sg-danger-chip">Retry in full graph<GitBranch className="h-3.5 w-3.5" /></Link>
        {resetFocusHref ? <Link href={resetFocusHref} className="sg-danger-chip">Clear focus<ArrowRight className="h-3.5 w-3.5" /></Link> : null}
      </div>
    </section>
  );
}
