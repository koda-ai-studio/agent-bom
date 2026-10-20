"use client";

import type { InventorySummaryResponse,OverviewResponse } from "@/lib/api";
import type {
ExecScoreDriver,
OverviewCoverageLane,
ServiceEntry,
ServiceId,
} from "@/lib/api-types";
import type { SeverityCounts } from "@/lib/dashboard-data";
import { type IssueSeverityMatrix } from "@/lib/finding-issue-type";
import Link from "next/link";
import { type ComponentProps } from "react";


export interface ExposurePathView {
  impactCategory?: string;
  affectedWorkloads?: string[];
  affectedServices?: string[];
  fixedVersion?: string;
  nodes: { type: "cve" | "package" | "server" | "agent" | "credential"; label: string; severity?: string }[];
  riskScore: number;
  href: string;
  key: string;
  /** Owner and remediation SLA of the ranked occurrence, when the risk source reports them. */
  ownership?: import("@/lib/finding-ownership").OwnershipFields;
}

export type OverviewComplianceFramework = {
  id: string;
  label: string;
  pass: number;
  warn: number;
  fail: number;
  total: number;
  kind: "scored" | "applicability";
  applicable?: number;
  notApplicable?: number;
};

export type OverviewComplianceSnapshot = {
  /** Percentage of EVALUATED controls passing — always render it next to
   *  `evaluatedControls` / `totalControls` so a small denominator is visible. */
  overallScore: number;
  overallStatus: "pass" | "warning" | "fail" | "no_data";
  evaluatedControls: number;
  totalControls: number;
  frameworks: OverviewComplianceFramework[];
};

export const SECTION_TITLE_CLASS =
  "text-lg font-semibold normal-case tracking-normal text-foreground";

export type PostureScoreFormat = "percent" | "points" | "grade";

export interface OverviewCockpitProps {
  localReport?: boolean | undefined;
  /** True until the posture and cross-domain overview requests settle. */
  loading?: boolean | undefined;
  overviewUnavailable?: boolean | undefined;
  inventorySummary?: InventorySummaryResponse | null | undefined;
  inventoryLoading?: boolean | undefined;
  inventoryUnavailable?: boolean | undefined;
  inventoryUnavailableHref?: string | undefined;
  complianceLoading?: boolean | undefined;
  scanScopeLoading?: boolean | undefined;
  grade: string;
  score?: number | undefined;
  /** Display-only score presentation. Defaults to a percentage. */
  scoreFormat?: PostureScoreFormat | undefined;
  /** Weighted inputs behind the score, for the "what influences this" panel. */
  scoreBreakdown?: ExecScoreDriver[] | null | undefined;
  scoreFloored?: boolean | undefined;
  /** Called when the user picks a display format; parent persists it (#3940). */
  onScoreFormatChange?: ((format: PostureScoreFormat) => void) | undefined;
  postureSummary?: string | undefined;
  postureTrend?: {
    direction: "improved" | "worsened" | "unchanged";
    delta: number;
    previousScore: number;
    points: number;
  } | null | undefined;
  critical: number;
  high: number;
  kev: number | null;
  /** KEV finding occurrences; `kev` is on the issue unit of the tiles. */
  kevOccurrences?: number | null | undefined;
  credentials: number | null;
  agents: number | null;
  scans: number | null;
  latestScan: string | null;
  mode: string;
  summaryReady: boolean;
  /** Honest scope shared by the headline and its finding drill-downs. */
  findingsScopeLabel?: string | undefined;
  severity: SeverityCounts;
  /** Severity × issue-type matrix (CVEs, misconfigs, secrets, identity). */
  issueMatrix?: IssueSeverityMatrix | null | undefined;
  domains: OverviewResponse["domains"] | null;
  /** Five security-posture coverage lanes (CSPM / Vuln / ASPM / DSPM /
   *  AISPM) with evidence-qualified, overlapping counts (issue #3946). */
  coverage?: OverviewCoverageLane[] | null | undefined;
  topPath: ExposurePathView | null;
  exposurePaths: ExposurePathView[];
  /** Set when exposurePaths come from the Investigation queue, in its order. */
  riskRanking?: { source: "queue"; total: number } | undefined;
  signals: {
    tools: number | null;
    packages: number | null;
    activeServices: number;
    connected: boolean;
  };
  compliance?: OverviewComplianceSnapshot | null | undefined;
  services?: Partial<Record<ServiceId, ServiceEntry>> | null | undefined;
}

export function FreshnessStatus({
  latestScan,
  scans,
  loading,
  localReport,
}: {
  latestScan: string | null;
  scans: number | null;
  loading: boolean;
  localReport: boolean;
}) {
  const label = localReport ? (latestScan ? "Report timestamp" : "Report timestamp unavailable") : loading
    ? "Loading scan evidence"
    : latestScan
    ? "Latest observed scan"
    : scans === 0
      ? "No completed scan evidence"
      : "Latest scan timestamp unavailable";

  return (
    <div
      data-testid="overview-freshness"
      role="status"
      className="mb-3 flex flex-wrap items-center gap-x-2 gap-y-1"
    >
      <div className="flex items-center gap-2">
        <span
          className="h-2 w-2 rounded-full bg-ink-tertiary"
          aria-hidden="true"
        />
        <span className="text-xs font-semibold text-foreground">{label}</span>
      </div>
      {loading ? (
        <span className="text-xs text-ink-secondary">
          Refreshing current evidence.
        </span>
      ) : latestScan ? (
        <time title="Newest observation in the displayed evidence. Other targets may have older or incomplete evidence." className="text-xs font-medium tabular-nums text-ink-secondary">
          {latestScan}
        </time>
      ) : (
        <span className="text-xs text-ink-secondary">
          {localReport ? "No timestamp reported in this file." : scans === 0 ? "Run a scan to establish freshness." : "The current evidence has no observed scan timestamp."}
        </span>
      )}
    </div>
  );
}

export function ReportEvidenceLink({ localReport, children, className, title, ...props }: ComponentProps<typeof Link> & { localReport: boolean }) {
  return localReport ? <div className={className} title={title}>{children}</div> : <Link {...props} className={className} title={title}>{children}</Link>;
}
