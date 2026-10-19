"use client";

import type {
OverviewCoverageLane,
ServiceId
} from "@/lib/api-types";
import { ArrowRight, Bot, Bug, Cloud, CodeXml, Database, Info, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { useId, useState, type ElementType } from "react";
import { OverviewCockpitProps } from "./shared";

export const COVERAGE_SEVERITY_BANDS: { key: keyof OverviewCoverageLane["severity"]; label: string }[] = [
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "low", label: "Low" },
  { key: "unrated", label: "Unrated" },
];

export const SECURITY_DISCIPLINES: Record<string, { label: string; icon: ElementType; order: number; accent: string; tile: string }> = {
  cspm: { label: "Cloud security (CSPM)", icon: Cloud, order: 0, accent: "text-sky-700 dark:text-sky-300", tile: "border-sky-600/35 bg-sky-500/5 dark:border-sky-400/35" },
  aspm: { label: "Application security (ASPM)", icon: CodeXml, order: 1, accent: "text-violet-700 dark:text-violet-300", tile: "border-violet-600/35 bg-violet-500/5 dark:border-violet-400/35" },
  vuln: { label: "Vulnerability management", icon: Bug, order: 2, accent: "text-orange-700 dark:text-orange-300", tile: "border-orange-600/35 bg-orange-500/5 dark:border-orange-400/35" },
  dspm: { label: "Data security (DSPM)", icon: Database, order: 3, accent: "text-cyan-700 dark:text-cyan-300", tile: "border-cyan-600/35 bg-cyan-500/5 dark:border-cyan-400/35" },
  aispm: { label: "AI security (AISPM)", icon: Bot, order: 4, accent: "text-teal-700 dark:text-teal-300", tile: "border-teal-600/35 bg-teal-500/5 dark:border-teal-400/35" },
};

export type LaneSource = { label: string; href: string };

export const CONNECT_CLOUD: LaneSource = { label: "Connect cloud account", href: "/connections?tab=connect" };

export const CONNECT_DATA: LaneSource = { label: "Connect a data source", href: "/connections?tab=connect" };

export const RUN_SCAN: LaneSource = { label: "Run a scan", href: "/scan" };

export function serviceActive(services: OverviewCockpitProps["services"], id: ServiceId): boolean {
  const state = services?.[id]?.state;
  return state === "connected" || state === "live";
}

export function missingLaneSource(
  domain: string,
  services: OverviewCockpitProps["services"],
  scans: number | null | undefined,
): LaneSource | null {
  if (domain === "cspm") {
    if (!services) return null;
    return serviceActive(services, "cloud_accounts") ? null : CONNECT_CLOUD;
  }
  if (domain === "dspm") {
    if (!services) return null;
    return serviceActive(services, "cloud_accounts") || serviceActive(services, "data_sources") ? null : CONNECT_DATA;
  }
  if (scans !== 0) return null;
  if (domain === "aispm" && (["local_agents", "fleet", "runtime_proxy", "runtime_gateway"] as const).some((id) => serviceActive(services, id))) {
    return null;
  }
  return RUN_SCAN;
}

export function SecurityCoverageLanes({
  coverage,
  services = null,
  scans = null,
}: {
  coverage?: OverviewCoverageLane[] | null | undefined;
  services?: OverviewCockpitProps["services"];
  scans?: number | null | undefined;
}) {
  const [showSeverity, setShowSeverity] = useState(false);
  const [showCoverageHelp, setShowCoverageHelp] = useState(false);
  const coverageHelpId = useId();
  const lanesId = useId();
  if (!coverage || coverage.length === 0) return null;
  return (
    <div className="@container pt-1" data-testid="overview-security-coverage">
      <div className="relative mb-3 flex items-center gap-2 text-xs leading-relaxed text-ink-secondary">
        <p>Findings may appear in multiple areas.</p>
        <button
          type="button"
          aria-label="About assessment coverage"
          aria-expanded={showCoverageHelp}
          aria-controls={coverageHelpId}
          aria-describedby={showCoverageHelp ? coverageHelpId : undefined}
          onClick={() => setShowCoverageHelp(!showCoverageHelp)}
          onBlur={() => setShowCoverageHelp(false)}
          onKeyDown={(event) => { if (event.key === "Escape") setShowCoverageHelp(false); }}
          className="shrink-0 rounded-md p-1 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-600"
        >
          <Info className="h-4 w-4" aria-hidden="true" />
        </button>
        {showCoverageHelp && (
          <span id={coverageHelpId} role="tooltip" className="absolute left-0 top-full z-10 mt-1 max-w-full rounded-lg border border-outline bg-surface p-3 text-ink shadow-lg">
            Zero findings does not establish assessment coverage.
          </span>
        )}
      </div>
      <button type="button" aria-expanded={showSeverity} aria-controls={lanesId} onClick={() => setShowSeverity(!showSeverity)} className="mb-2 rounded-md py-1 text-xs font-medium text-emerald-700 dark:text-emerald-300">
        {showSeverity ? "Hide severity breakdown" : "Show severity breakdown"}
      </button>
      <div id={lanesId} className="grid grid-cols-1">
        {[...coverage].sort((left, right) => (SECURITY_DISCIPLINES[left.domain]?.order ?? 5) - (SECURITY_DISCIPLINES[right.domain]?.order ?? 5)).map((lane) => {
          const discipline = SECURITY_DISCIPLINES[lane.domain];
          const Icon = discipline?.icon ?? ShieldCheck;
          const known = lane.evidence_status !== undefined;
          const exact = lane.evidence_status === "complete" && lane.count_exact !== false;
          const statusLabel = lane.evidence_status === "partial" ? "Partial count" : "Count unavailable";
          const total = COVERAGE_SEVERITY_BANDS.reduce((sum, band) => sum + (lane.severity[band.key] || 0), 0);
          const bands = COVERAGE_SEVERITY_BANDS.filter((band) => (lane.severity[band.key] || 0) > 0);
          const missing = exact && total === 0 ? missingLaneSource(lane.domain, services, scans) : null;
          if (missing) {
            return (
              <div key={lane.domain} data-testid={`coverage-lane-${lane.domain}`}
                className="grid min-w-0 grid-cols-[minmax(0,1fr)_auto] items-center gap-3 border-b border-outline px-2 py-3">
                <div className="min-w-0">
                  <span className="flex items-start gap-2 text-sm font-semibold text-foreground"><Icon className={`mt-0.5 h-4 w-4 shrink-0 ${discipline?.accent ?? "text-ink-secondary"}`} aria-hidden="true" /><span>{discipline?.label ?? lane.label}</span></span>
                  <p className="ml-6 mt-1 text-xs text-ink-secondary">Not connected</p>
                </div>
                <Link href={missing.href}
                  className="inline-flex min-h-8 items-center gap-1 rounded-md border border-outline bg-surface-muted px-2.5 py-1 text-xs font-medium text-foreground transition hover:border-outline-strong focus-visible:outline-2 focus-visible:outline-offset-2">
                  {missing.label}<ArrowRight className="h-3 w-3" aria-hidden="true" />
                </Link>
              </div>
            );
          }
          return (
            <Link
              key={lane.domain}
              href={lane.href}
              data-testid={`coverage-lane-${lane.domain}`}
              className="min-w-0 rounded-md border-b border-outline px-2 py-3 transition-colors hover:bg-surface-muted focus-visible:outline-2 focus-visible:outline-offset-2"
            >
              <div className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-3">
                <span className="flex items-start gap-2 text-sm font-semibold text-foreground"><Icon className={`mt-0.5 h-4 w-4 shrink-0 ${discipline?.accent ?? "text-ink-secondary"}`} aria-hidden="true" /><span>{discipline?.label ?? lane.label}</span></span>
                {/* The unit is not decoration. A bare "1610" under a heading
                    called CSPM reads as assets, accounts, VMs or data stores
                    depending on the reader — every one of which is wrong. These
                    are FINDINGS in that posture lane, which is also what the
                    severity chips below sum to. */}
                {known && total > 0 ? <span className="flex flex-col items-end gap-0.5">
                  <span className="text-sm font-semibold tabular-nums text-foreground">
                    {known && total > 0 ? `${exact ? "" : "≥"}${lane.count.toLocaleString()}` : "—"}
                  </span>
                  {known && total > 0 ? (
                    <span className="text-xs font-medium uppercase tracking-[0.08em] text-ink-secondary">
                      {lane.count === 1 ? "finding" : "findings"}
                    </span>
                  ) : null}
                </span> : null}
              </div>
              <div className="ml-6 mt-1 min-w-0">
                {!exact && known && total > 0 ? (
                  <p className="mb-1 text-xs text-ink-secondary">{statusLabel} · at least this many</p>
                ) : null}
              <div className="flex flex-wrap gap-1">
                {!known || total === 0 ? (
                  <span className="text-xs text-ink-secondary">{exact ? "No open findings" : statusLabel}</span>
                ) : (
                  bands.map((band) => (
                    <span
                      key={band.key}
                      className="text-xs font-medium tabular-nums text-ink-secondary"
                      hidden={!showSeverity}
                    >
                      {band.label} {lane.severity[band.key]}
                    </span>
                  ))
                )}
              </div>
              </div>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
