"use client";

import Link from "next/link";
import { ArrowRight, ChevronDown, GitBranch } from "lucide-react";

import { AdvisoryFreshness } from "@/components/advisory-freshness";
import { GraphLensSwitcher } from "@/components/graph-lens-switcher";
import { GraphSnapshotReceipt } from "@/components/graph-snapshot-receipt";
import { InvestigationExportButton } from "@/components/investigation-export-button";
import type { GraphSnapshot } from "@/lib/api";
import type { ExposurePath } from "@/lib/exposure-path";

export type InvestigationQuestion = "credentials" | "critical" | null;

/** Secondary scope, view and export controls, collapsed into one toolbar menu that overlays rather than pushes content. */
export function InvestigationExploreMenu({ question, onQuestion, onBlastRadius, snapshot, scanId, exposurePath, fullGraphHref }: {
  question: string | null;
  onQuestion: (next: InvestigationQuestion) => void;
  onBlastRadius: () => void;
  snapshot: GraphSnapshot | null;
  scanId: string;
  exposurePath: ExposurePath | null;
  fullGraphHref: string;
}) {
  return (
    <details className="investigation-navigation group sm:relative">
      <summary className="inline-flex cursor-pointer list-none items-center gap-1.5 rounded-lg border border-outline bg-surface px-3 py-1.5 text-xs font-medium text-foreground hover:bg-surface-muted [&::-webkit-details-marker]:hidden">
        Explore &amp; evidence <ChevronDown className="h-3.5 w-3.5 transition group-open:rotate-180" aria-hidden="true" />
      </summary>
      <div data-testid="investigation-explore-panel" className="absolute inset-x-0 top-full z-30 mt-2 space-y-3 rounded-xl border border-outline bg-surface p-3 shadow-lg sm:inset-x-auto sm:right-0 sm:top-auto sm:w-[min(36rem,calc(100vw-2rem))]">
        <p className="text-xs text-ink-tertiary">Scope, views and exports</p>
        <div role="group" aria-label="Investigation starting questions" className="flex flex-wrap gap-2">
          <button type="button" className="sg-action" aria-pressed={!question} onClick={() => onQuestion(null)}>All ranked paths</button>
          <button type="button" className="sg-action" aria-pressed={question === "credentials"} onClick={() => onQuestion("credentials")}>Credential exposure</button>
          <button type="button" className="sg-action" aria-pressed={question === "critical"} onClick={() => onQuestion("critical")}>Critical dependencies</button>
          <button type="button" className="sg-action" onClick={onBlastRadius}>Potential blast radius</button>
        </div>
        <GraphLensSwitcher variant="compact" />
        <GraphSnapshotReceipt snapshot={snapshot} scanId={scanId} />
        <AdvisoryFreshness />
        <div className="flex flex-wrap gap-2">
          <InvestigationExportButton path={exposurePath} scanId={scanId} />
          <Link href={fullGraphHref} className="sg-action">Open lineage lens <GitBranch className="h-4 w-4" /></Link>
          <Link href="/remediation" className="sg-action">Remediation <ArrowRight className="h-4 w-4" /></Link>
        </div>
      </div>
    </details>
  );
}
