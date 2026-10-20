"use client";

import { Collapsible } from "@/components/collapsible";
import { isNotEvaluated } from "@/components/compliance-status";
import { FrameworkIcon } from "@/components/framework-icon";
import { controlFrameworksLabel, formatFrameworkCoverage, frameworkCoverageCounts } from "@/lib/framework-coverage";
import { CircleCheck, CircleX, SearchCheck } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { OverviewComplianceFramework, OverviewComplianceSnapshot } from "./shared";

export function frameworkEvaluated(framework: OverviewComplianceFramework): number {
  if (framework.kind === "applicability") return 0;
  return framework.pass + framework.warn + framework.fail;
}

export function hasEvaluatedCompliance(compliance: OverviewComplianceSnapshot | null | undefined): boolean {
  if (!compliance || isNotEvaluated(compliance.overallStatus)) return false;
  return compliance.frameworks.some((framework) => frameworkEvaluated(framework) > 0);
}

export function ComplianceSnapshotPanel({
  compliance,
  hasScanEvidence = false,
  loading = false,
  scanScopeKnown = true,
}: {
  compliance: OverviewComplianceSnapshot | null | undefined;
  hasScanEvidence?: boolean | undefined;
  loading?: boolean | undefined;
  scanScopeKnown?: boolean | undefined;
}) {
  const [showAllFrameworks, setShowAllFrameworks] = useState(false);
  const allFrameworks = compliance?.frameworks ?? [];
  // Show the largest observed control gaps first; never infer certification status.
  const scored = allFrameworks.filter((item) => item.kind === "scored")
    .sort((a, b) => (b.fail + b.warn) - (a.fail + a.warn));
  const mappings = allFrameworks.filter((item) => item.kind === "applicability");
  const evidenceReady = hasScanEvidence && compliance != null && hasEvaluatedCompliance(compliance);
  const attention = scored.filter((item) => item.fail > 0 || item.warn > 0).length;
  const passed = scored.reduce((total, item) => total + item.pass, 0);
  const unassessed = scored.filter((item) => frameworkEvaluated(item) === 0).length;
  const assessmentCoverage = evidenceReady
    && Number.isInteger(compliance.evaluatedControls) && compliance.evaluatedControls >= 0
    && Number.isInteger(compliance.totalControls) && compliance.totalControls > 0
    && compliance.evaluatedControls <= compliance.totalControls
    ? Math.round(100 * compliance.evaluatedControls / compliance.totalControls)
    : null;

  return (
    <div data-testid="overview-compliance-snapshot">
      {loading ? (
        <p role="status" className="mt-2 text-xs text-ink-secondary">Loading control evaluation…</p>
      ) : evidenceReady ? (
        <>
          <dl className="mt-3 grid grid-cols-3 gap-2" aria-label="Evaluated control results">
            {[
              { label: "Controls passed", value: passed, tone: "text-emerald-700 dark:text-emerald-200", Icon: CircleCheck },
              { label: "Controls failed", value: scored.reduce((n, f) => n + f.fail, 0), tone: "text-red-700 dark:text-red-200", Icon: CircleX },
              { label: "Controls need review", value: scored.reduce((n, f) => n + f.warn, 0), tone: "text-amber-800 dark:text-amber-200", Icon: SearchCheck },
            ].map(({ label, value, tone, Icon }) => (
              <div key={label} className="compliance-metric min-w-0 rounded-lg border border-outline p-3">
                <dt className="text-xs leading-snug text-ink-secondary">{label}</dt>
                <dd className={`mt-2 flex flex-wrap items-center gap-2 text-2xl font-semibold tabular-nums ${tone}`}>
                  <Icon aria-hidden="true" className="h-4 w-4 shrink-0" />{value}
                </dd>
              </div>
            ))}
          </dl>
          <div className="mt-2 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1 text-xs text-ink-secondary">
            <p>{passed}/{compliance.evaluatedControls} evaluated controls pass</p>
            <p data-testid="overview-compliance-pass-context">
              <span className="font-medium text-foreground">{Math.round(compliance.overallScore)}% pass rate</span>
              {assessmentCoverage != null ? ` · ${compliance.evaluatedControls} of ${compliance.totalControls} controls assessed (${assessmentCoverage}%)` : ""}
              {` · ${scored.length - unassessed} of ${controlFrameworksLabel(scored.length)} evaluated`}
            </p>
          </div>

        </>
      ) : (
        <p className="mt-2 text-xs text-ink-secondary">
          {!scanScopeKnown
            ? "Control evaluation unavailable. Scan scope could not be established."
            : hasScanEvidence
            ? "Control evaluation unavailable for completed scans. Review scan scope and evaluation status before drawing a compliance conclusion."
            : "Framework coverage appears after the first completed scan. Empty estates do not show pass tiles."}
        </p>
      )}
      {!loading && hasScanEvidence && compliance ? (
        <details className="mt-2 text-xs text-ink-secondary">
          <summary className="cursor-pointer rounded-sm focus-visible:outline-2 focus-visible:outline-emerald-500">
            {assessmentCoverage == null ? "Assessment coverage unavailable" : `Assessment: ${compliance.evaluatedControls}/${compliance.totalControls} framework control entries evaluated (${assessmentCoverage}%)`}
          </summary>
          <p className="mt-2 leading-relaxed">Entries are counted per framework and may overlap. Recorded evaluations can include check errors. Coverage is limited to the framework entries returned for this assessment.</p>
        </details>
      ) : null}
      {!loading && hasScanEvidence && scored.length > 0 ? (
        <div className="mt-3 border-t border-outline pt-3">
          {evidenceReady ? <p className="mb-2 text-xs text-ink-secondary">{attention} framework{attention === 1 ? " needs" : "s need"} attention{unassessed > 0 ? ` · ${unassessed} not evaluated` : ""}</p> : null}
          <Collapsible bare title="Control frameworks" subtitle={`${formatFrameworkCoverage(frameworkCoverageCounts(allFrameworks))} · ordered by failing and warning checks`} defaultOpen data-testid="overview-evaluated-frameworks">
            <div role="region" aria-label="Control framework list" tabIndex={showAllFrameworks ? 0 : undefined}
              className="max-h-[min(50vh,22rem)] overflow-y-auto overscroll-contain rounded-md focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-500">
              <FrameworkCards frameworks={showAllFrameworks ? scored : scored.slice(0, 4)} />
            </div>
            {scored.length > 4 ? (
              <button type="button" className="mt-2 text-xs text-emerald-700 dark:text-emerald-300"
                aria-expanded={showAllFrameworks} onClick={() => setShowAllFrameworks(!showAllFrameworks)}>
                {showAllFrameworks ? "Show priority frameworks" : `Show all ${scored.length} control frameworks`}
              </button>
            ) : null}
          </Collapsible>
        </div>
      ) : null}
      {hasScanEvidence && mappings.length > 0 ? (
        <Collapsible bare title="Risk mappings" count={mappings.length} subtitle="Applicability, separate from control pass/fail" defaultOpen={!evidenceReady} data-testid="overview-risk-mappings">
          <div className="grid gap-2 sm:grid-cols-2">
            {mappings.slice(0, 4).map((framework) => (
              <Link key={framework.id} href={`/compliance?framework=${encodeURIComponent(framework.id)}`} className="flex min-w-0 items-center gap-2 rounded-md py-2 hover:bg-surface-muted">
                <span aria-hidden="true"><FrameworkIcon frameworkId={framework.id} size={24} /></span>
                <span className="min-w-0 text-sm font-semibold text-foreground">{framework.label}
                  <span className="mt-1 block font-normal text-ink-secondary">{framework.applicable ?? 0}/{framework.total} risks applicable</span>
                </span>
              </Link>
            ))}
          </div>
          {mappings.length > 4 ? <Collapsible bare title={`More risk mappings (${mappings.length - 4})`} defaultOpen={false}><FrameworkCards frameworks={mappings.slice(4)} /></Collapsible> : null}
        </Collapsible>
      ) : null}
    </div>
  );
}

export function FrameworkCards({ frameworks }: { frameworks: OverviewComplianceSnapshot["frameworks"] }) {
  return (
        <div className="grid gap-x-4 gap-y-1 sm:grid-cols-2" data-testid="overview-framework-cards">
          {frameworks.map((framework) => {
            const evaluated = frameworkEvaluated(framework);
            const isApplicability = framework.kind === "applicability";
            // 0 evaluated controls is NOT a pass — surface a neutral
            // "not evaluated" state so an unscored framework never reads green.
            return (
              <Link
                key={framework.id}
                href={`/compliance?framework=${encodeURIComponent(framework.id)}`}
                className="grid min-h-12 grid-cols-[1.75rem_minmax(0,1fr)] items-center gap-2 border-b border-outline px-1.5 py-2 transition hover:bg-surface-muted"
              >
                <span aria-hidden="true" className="flex h-7 w-7 items-center justify-center">
                  <FrameworkIcon frameworkId={framework.id} size={28} />
                </span>
                <div className="min-w-0">
                  <p className="text-sm font-semibold leading-snug text-foreground">
                    {framework.label}
                  </p>
                  <p className="mt-0.5 text-sm leading-snug text-ink-secondary">
                    {isApplicability
                      ? `${framework.applicable ?? 0}/${framework.total} risks applicable`
                      : evaluated === 0
                      ? `Not evaluated · 0/${framework.total} controls`
                      : `${framework.pass}/${evaluated} evaluated controls pass${framework.fail > 0 ? ` · ${framework.fail} failed` : ""}${framework.warn > 0 ? ` · ${framework.warn} need review` : ""}`}
                  </p>
                </div>

              </Link>
            );
          })}
        </div>
  );
}
