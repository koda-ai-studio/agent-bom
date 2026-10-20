import Link from "next/link";
import { ArrowRight, GitBranch } from "lucide-react";

import { GraphEmptyState } from "@/components/graph-state-panels";
import type { QueueStateCopy } from "@/lib/investigation-queue-copy";

/** The attack-path queue could not load: say so, and offer the full graph and a focus reset. */
export function InvestigationLoadError({ copy, retryHref, resetFocusHref }: { copy: QueueStateCopy; retryHref: string; resetFocusHref: string | null }) {
  return (
    <section className="rounded-3xl border border-[color:var(--severity-critical-border)] bg-[color:var(--severity-critical-bg)] p-4">
      <GraphEmptyState title={copy.title} detail={copy.detail} suggestions={copy.suggestions} command="agent-bom serve --api" />
      <div className="mt-4 flex flex-wrap gap-3 border-t border-red-900/40 pt-4">
        <Link href={retryHref} className="sg-danger-chip">Retry in full graph<GitBranch className="h-3.5 w-3.5" /></Link>
        {resetFocusHref ? <Link href={resetFocusHref} className="sg-danger-chip">Clear focus<ArrowRight className="h-3.5 w-3.5" /></Link> : null}
      </div>
    </section>
  );
}
