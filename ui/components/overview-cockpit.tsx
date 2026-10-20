"use client";

import { Collapsible } from "@/components/collapsible";
import { DetailTabs } from "@/components/detail-tabs";
import { OverviewAssets } from "@/components/overview-assets";
import { ArrowRight } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { ComplianceSnapshotPanel, hasEvaluatedCompliance } from "./overview/compliance";
import { SecurityCoverageLanes } from "./overview/coverage";
import { SeverityIssueStrip } from "./overview/issue-strip";
import { PostureHero, ScoreExplainer } from "./overview/posture-score";
import { TopRisksPanel } from "./overview/risks";
import { FreshnessStatus, OverviewCockpitProps, SECTION_TITLE_CLASS } from "./overview/shared";

export function OverviewCockpit({
  localReport = false,
  loading = false,
  overviewUnavailable = false,
  inventorySummary = null,
  inventoryLoading = false,
  inventoryUnavailable = false,
  inventoryUnavailableHref = "/inventory",
  complianceLoading = false,
  scanScopeLoading = false,
  grade,
  score,
  scoreFormat = "percent",
  scoreBreakdown = null,
  scoreFloored,
  onScoreFormatChange,
  postureSummary,
  postureTrend = null,
  critical,
  high,
  kev,
  kevOccurrences = null,
  credentials,
  agents,
  scans,
  latestScan,
  summaryReady,
  findingsScopeLabel,
  severity,
  issueMatrix = null,
  domains,
  coverage = null,
  topPath,
  exposurePaths,
  compliance = null,
  services = null,
}: OverviewCockpitProps) {
  const [riskTab, setRiskTab] = useState<"risks" | "posture" | "assets">("posture");
  const hasScanEvidence = Boolean(summaryReady && scans && scans > 0);
  // Once scans exist the chip always renders, but an unevidenced score reads as
  // an em dash — the SAME treatment the Trust Center gives this status. Hiding
  // the chip instead would leave the reader unable to tell "not measured" from
  // "not loaded"; printing the raw percentage claimed compliance we never
  // evidenced.
  const complianceEvaluated = hasScanEvidence && compliance != null && hasEvaluatedCompliance(compliance);
  const complianceScore = complianceEvaluated
    ? `${Math.round(compliance.overallScore)}%`
    : hasScanEvidence && compliance != null
      ? "—"
      : undefined;

  return (
    <div className="space-y-7">
      {localReport && <p className="text-sm text-ink-secondary">Local report only. Findings are not linked to tenant investigations or live coverage.</p>}
      <section aria-label="Risk overview" className="@container min-w-0 rounded-2xl border border-outline-strong bg-surface p-4 sm:p-5">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h2 className={SECTION_TITLE_CLASS}>Risk overview</h2>
          <FreshnessStatus latestScan={latestScan} scans={scans} loading={loading} localReport={localReport} />
        </div>
        <DetailTabs ariaLabel="Risk overview views" value={riskTab} onChange={setRiskTab}
          tabs={[{ key: "posture", label: "Posture" }, { key: "risks", label: "Top risks" }, { key: "assets", label: "Assets & coverage" }]} />
        <div role="tabpanel" aria-label="Top risks" hidden={riskTab !== "risks"}>
          <TopRisksPanel localReport={localReport} loading={loading} unavailable={overviewUnavailable} scans={scans}
            topPath={topPath} exposurePaths={exposurePaths}
            agentMeshHref={agents != null && agents > 0 ? "/agents/topology" : null} />
        </div>
        <div role="tabpanel" aria-label="Assets & coverage" hidden={riskTab !== "assets"}>{localReport ? <p className="mt-4 text-sm text-ink-secondary">This report is not linked to a live inventory snapshot.</p> : <OverviewAssets summary={inventorySummary} loading={inventoryLoading} unavailable={inventoryUnavailable} unavailableHref={inventoryUnavailableHref} />}</div>
        <div role="tabpanel" aria-label="Posture" hidden={riskTab !== "posture"}>
            <div className="mt-4 grid items-start gap-5 @min-[56rem]:grid-cols-[minmax(0,2fr)_minmax(0,3fr)] @min-[56rem]:gap-6">
              <PostureHero
                localReport={localReport}
                loading={loading}
                grade={grade}
                score={score}
                scoreFormat={scoreFormat}
                onScoreFormatChange={onScoreFormatChange}
                summary={postureSummary}
                trend={postureTrend}
                critical={critical}
                high={high}
                severity={severity}
              />
              <SeverityIssueStrip
                localReport={localReport}
                summaryReady={summaryReady}
                critical={critical}
                high={high}
                kev={kev}
                kevOccurrences={kevOccurrences}
                credentials={credentials}
                complianceScore={complianceScore}
                severity={severity}
                matrix={issueMatrix}
                scopeLabel={findingsScopeLabel}
              />
            </div>

            {/* 1b — What influences the score: read-only weighted-input breakdown
                so the grade is legible, not opaque (#3940). */}
            <ScoreExplainer breakdown={scoreBreakdown} grade={grade} floored={scoreFloored} />
        </div>
      </section>
      <div className="grid items-start gap-6 xl:grid-cols-2 xl:items-stretch">
        <section aria-label="Compliance & frameworks" className="min-w-0 rounded-2xl border border-outline bg-surface p-5 sm:p-6">
          <Collapsible bare title="Compliance & frameworks" titleClassName={SECTION_TITLE_CLASS} defaultOpen
            actions={localReport ? undefined : <Link href="/compliance" aria-label="View all frameworks" title="View all frameworks" className="inline-flex min-h-8 min-w-8 items-center justify-center gap-1 text-xs text-emerald-700 dark:text-emerald-300"><span className="hidden sm:inline">View all frameworks</span><ArrowRight className="h-4 w-4" aria-hidden="true" /></Link>}>
            {localReport ? <p className="text-sm text-ink-secondary">Tenant compliance assessment is unavailable for this local report.</p> : <ComplianceSnapshotPanel compliance={compliance} hasScanEvidence={hasScanEvidence}
              loading={loading || complianceLoading || scanScopeLoading} scanScopeKnown={scans !== null} />}
          </Collapsible>
        </section>
        <section aria-label="Findings by security area" className="min-w-0 rounded-2xl border border-outline bg-surface p-5 sm:p-6">
          <Collapsible bare title="Findings by security area" titleClassName={SECTION_TITLE_CLASS} defaultOpen>
            {loading && !domains ? (
              <p role="status" className="mt-3 text-sm text-ink-secondary">Loading coverage…</p>
            ) : overviewUnavailable && !domains ? (
              <p role="status" className="mt-3 text-sm text-ink-secondary">Coverage unavailable.</p>
            ) : <SecurityCoverageLanes coverage={coverage} services={services} scans={scans} />}
          </Collapsible>
        </section>
      </div>
    </div>
  );
}

export type { ExposurePathView,OverviewCockpitProps,OverviewComplianceFramework,OverviewComplianceSnapshot,PostureScoreFormat } from "./overview/shared";
