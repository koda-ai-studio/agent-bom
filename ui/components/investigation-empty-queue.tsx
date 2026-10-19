"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import { ArrowRight, GitBranch } from "lucide-react";

import { GraphAnalysisStatusBanner } from "@/components/graph-analysis-status";
import { GraphEmptyState } from "@/components/graph-state-panels";
import { showAnalysisBannerForEmptyQueue } from "@/lib/finding-path-focus";
import type { GraphAnalysisStatus } from "@/lib/graph-schema";

/** The investigation queue had no path for the current focus: say why and offer the next scope. */
export function InvestigationEmptyQueue({
  analysisStatus,
  copy,
  suggestions,
  tenantHasGraphData,
  continuation,
  neighbourhood,
  relatedHref,
  fullGraphHref,
  findingsHref,
  resetFocusHref,
}: {
  analysisStatus: GraphAnalysisStatus | undefined;
  copy: { title: string; detail: string };
  suggestions: string[];
  tenantHasGraphData: boolean;
  continuation: ReactNode;
  neighbourhood: { href: string; label: string } | null;
  relatedHref: string | null;
  fullGraphHref: string;
  findingsHref: string;
  resetFocusHref: string | null;
}) {
  return (
    <section className="rounded-3xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
      {showAnalysisBannerForEmptyQueue(analysisStatus) ? (
        <div className="mb-4">
          <GraphAnalysisStatusBanner status={analysisStatus} />
        </div>
      ) : null}
      <GraphEmptyState
        title={copy.title}
        detail={copy.detail}
        suggestions={suggestions}
        command={tenantHasGraphData ? undefined : "agent-bom scan -p . -f graph"}
      />
      {continuation}
      <div className="mt-4 flex flex-wrap gap-3 border-t border-[color:var(--border-subtle)] pt-4">
        {neighbourhood ? (
          <Link href={neighbourhood.href} className="sg-action">
            {neighbourhood.label}
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        ) : null}
        {relatedHref ? (
          <Link href={relatedHref} className="sg-action">
            Show related package and advisory paths
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        ) : null}
        <Link href={fullGraphHref} className="sg-filter-chip">
          Open full graph
          <GitBranch className="h-3.5 w-3.5" />
        </Link>
        <Link href={findingsHref} className="sg-filter-chip">
          Review findings
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
        {resetFocusHref ? (
          <Link href={resetFocusHref} className="sg-filter-chip">
            Clear focus
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        ) : null}
      </div>
    </section>
  );
}
