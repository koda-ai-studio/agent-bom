"use client";

import { Collapsible } from "@/components/collapsible";
import type { SeverityCounts } from "@/lib/dashboard-data";
import {
  ISSUE_TYPE_SHORT,
  emptyIssueSeverityMatrix,
  findingsHref,
  type IssueSeverityMatrix,
  type IssueType,
  type SeverityBand,
} from "@/lib/finding-issue-type";
import { Bug, Fingerprint, Flame, KeyRound, ShieldCheck, SlidersHorizontal, UserRound } from "lucide-react";
import { type ElementType } from "react";
import { ReportEvidenceLink, SECTION_TITLE_CLASS } from "./shared";

export const ISSUE_TYPE_GLYPH: Record<IssueType, ElementType> = {
  vulnerability: Bug,
  misconfiguration: SlidersHorizontal,
  secret: KeyRound,
  pii: UserRound,
  identity: Fingerprint,
  unclassified: Bug,
};

export const ISSUE_TYPE_BAR: Record<IssueType, string> = {
  vulnerability: "bg-ink-secondary",
  misconfiguration: "bg-ink-tertiary",
  secret: "bg-ink-secondary opacity-60",
  pii: "bg-ink-secondary opacity-45",
  identity: "bg-ink-tertiary opacity-50",
  unclassified: "bg-ink-tertiary opacity-35",
};

export function CategoryChip({
  localReport = false,
  href,
  icon: Icon,
  label,
  value,
  title,
}: {
  localReport?: boolean | undefined;
  href: string;
  icon: ElementType;
  label: string;
  value: number | string;
  title?: string | undefined;
}) {
  return (
    <ReportEvidenceLink localReport={localReport}
      href={href}
      title={title}
      className="inline-flex items-center gap-1 rounded-full border border-outline bg-surface-muted px-2 py-0.5 text-xs font-semibold text-ink-secondary transition hover:border-outline-strong hover:text-foreground"
    >
      <Icon className="h-3 w-3 text-ink-secondary" aria-hidden="true" />
      {label} {value}
    </ReportEvidenceLink>
  );
}

/** KEV is counted in issues, like the tiles; occurrences are named, never a bare second total. */
export function kevChipTitle(issues: number, occurrences: number | null | undefined): string {
  const issueText = `${issues.toLocaleString()} known-exploited issue${issues === 1 ? "" : "s"} (CISA KEV)`;
  return occurrences != null && occurrences !== issues ? `${issueText} · ${occurrences.toLocaleString()} occurrences` : issueText;
}

export function SeverityIssueStrip({
  localReport = false,
  summaryReady,
  critical,
  high,
  kev,
  kevOccurrences = null,
  credentials,
  complianceScore,
  severity,
  matrix,
  scopeLabel,
}: {
  localReport?: boolean | undefined;
  summaryReady: boolean;
  critical: number;
  high: number;
  kev: number | null;
  kevOccurrences?: number | null | undefined;
  credentials: number | null;
  complianceScore?: string | undefined;
  severity: SeverityCounts;
  matrix: IssueSeverityMatrix | null | undefined;
  scopeLabel?: string | undefined;
}) {
  const resolved = matrix ?? emptyIssueSeverityMatrix();
  const hasTyped = resolved.openTotal > 0;
  const bands: { key: SeverityBand; label: string; tone: string; tint: string; value: number }[] = [
    {
      key: "critical",
      label: "Critical",
      tone: "text-red-800 dark:text-red-200",
      tint: "border-[color:var(--severity-critical-border)] bg-[color:var(--severity-critical-bg)] hover:border-[color:var(--severity-critical)]",
      value: summaryReady ? (hasTyped ? resolved.totals.critical : critical) : 0,
    },
    {
      key: "high",
      label: "High",
      tone: "text-orange-800 dark:text-orange-200",
      tint: "border-[color:var(--severity-high-border)] bg-[color:var(--severity-high-bg)] hover:border-[color:var(--severity-high)]",
      value: summaryReady ? (hasTyped ? resolved.totals.high : high) : 0,
    },
    {
      key: "medium",
      label: "Medium",
      tone: "text-amber-800 dark:text-amber-200",
      tint: "border-[color:var(--severity-medium-border)] bg-[color:var(--severity-medium-bg)] hover:border-[color:var(--severity-medium)]",
      value: summaryReady ? (hasTyped ? resolved.totals.medium : severity.medium) : 0,
    },
    {
      key: "low",
      label: "Low",
      tone: "text-blue-800 dark:text-blue-200",
      tint: "border-[color:var(--severity-low-border)] bg-[color:var(--severity-low-bg)] hover:border-[color:var(--severity-low)]",
      value: summaryReady ? (hasTyped ? resolved.totals.low : severity.low) : 0,
    },
  ];
  const stackedTotal = bands.reduce((sum, band) => sum + band.value, 0);
  const issueTypes: IssueType[] = ["vulnerability", "misconfiguration", "secret", "pii", "identity", "unclassified"];

  return (
    <div
      className="@container min-w-0 border-t border-outline pt-3 @min-[56rem]:border-t-0 @min-[56rem]:border-l @min-[56rem]:pt-0 @min-[56rem]:pl-6"
      data-testid="overview-severity-issue-strip"
    >
      <Collapsible
        bare
        title="Open issues"
        titleClassName={SECTION_TITLE_CLASS}
        subtitle={scopeLabel ?? "By severity and issue class"}
        defaultOpen
      >
          <div className="mb-3 flex flex-wrap items-center gap-1.5">
            {/* Category chips are neutral + iconified: hue is reserved for
                severity alone, so a category never mimics a severity band
                (KEV is not amber, Secrets is not red, Compliance is not a
                green pass). The glyph carries the distinction. */}
            {summaryReady && kev != null ? (
              <CategoryChip
                localReport={localReport}
                href={findingsHref({ scope: "all", kev: true })}
                icon={Flame}
                label="KEV"
                value={kev}
                title={kevChipTitle(kev, kevOccurrences)}
              />
            ) : null}
            {summaryReady && credentials != null ? (
              <CategoryChip
                localReport={localReport}
                href={findingsHref({ scope: "all", issue: "secret" })}
                icon={KeyRound}
                label="Secrets"
                value={credentials}
                title="Findings that expose credentials or secrets"
              />
            ) : null}
            {complianceScore ? (
              <CategoryChip
                localReport={localReport}
                href="/compliance"
                icon={ShieldCheck}
                label="Compliance"
                value={complianceScore}
                title={
                  complianceScore === "—"
                    ? "No framework was substantively evaluated — nothing to score"
                    : "Overall compliance score across evaluated frameworks"
                }
              />
            ) : null}
          </div>
      <div className="mb-3 mt-1 flex h-2.5 overflow-hidden rounded-full bg-surface">
        {summaryReady && stackedTotal > 0 ? (
          bands.map((band) =>
            band.value > 0 ? (
              <div
                key={band.key}
                className={
                  band.key === "critical"
                    ? "bg-[color:var(--severity-critical)]"
                    : band.key === "high"
                      ? "bg-[color:var(--severity-high)]"
                      : band.key === "medium"
                        ? "bg-[color:var(--severity-medium)]"
                        : "bg-[color:var(--severity-low)]"
                }
                style={{ width: `${(band.value / stackedTotal) * 100}%` }}
                title={`${band.label}: ${band.value}`}
              />
            ) : null,
          )
        ) : (
          <div className="w-full bg-[color:var(--status-success)]/35" />
        )}
      </div>

      <div className="grid grid-cols-2 gap-2 @min-[36rem]:grid-cols-4">
        {bands.map((band) => (
          <ReportEvidenceLink localReport={localReport}
            key={band.key}
            href={findingsHref({ scope: "all", severity: band.key })}
            className={`grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-2 rounded-lg border px-2.5 py-2 transition ${band.tint}`}
          >
            <p className="text-xs font-semibold uppercase tracking-[0.08em] text-ink-secondary">
              {band.label}
            </p>
            <p className={`font-mono text-xl font-semibold ${band.tone}`}>
              {summaryReady ? band.value : "—"}
            </p>
            {hasTyped && summaryReady ? (
              <div className="col-span-2 mt-2 space-y-1">
                <div className="flex h-1.5 overflow-hidden rounded-full bg-surface-muted">
                  {issueTypes.map((issue) => {
                    const count = resolved[issue][band.key];
                    if (count <= 0 || band.value <= 0) return null;
                    return (
                      <div
                        key={issue}
                        className={ISSUE_TYPE_BAR[issue]}
                        style={{ width: `${(count / band.value) * 100}%` }}
                        title={`${ISSUE_TYPE_SHORT[issue]}: ${count}`}
                      />
                    );
                  })}
                </div>
                <div className="flex flex-wrap gap-x-1.5 gap-y-0.5 text-xs text-ink-secondary">
                  {issueTypes.map((issue) => {
                    const count = resolved[issue][band.key];
                    if (count <= 0) return null;
                    const Glyph = ISSUE_TYPE_GLYPH[issue];
                    return (
                      <span key={issue} className="inline-flex items-center gap-0.5">
                        <Glyph className="h-2.5 w-2.5" aria-hidden="true" />
                        {ISSUE_TYPE_SHORT[issue]} {count}
                      </span>
                    );
                  })}
                </div>
              </div>
            ) : null}
          </ReportEvidenceLink>
        ))}
      </div>

      {hasTyped && summaryReady ? (
        <div className="mt-3 flex flex-wrap gap-2 border-t border-outline pt-2.5">
          {issueTypes.map((issue) => {
            const total = resolved.byType[issue];
            if (total <= 0) return null;
            const Glyph = ISSUE_TYPE_GLYPH[issue];
            return (
              <ReportEvidenceLink localReport={localReport}
                key={issue}
                href={findingsHref({ scope: "all", issue })}
                className="inline-flex items-center gap-1.5 rounded-full border border-outline bg-surface px-2 py-0.5 text-xs text-ink-secondary transition hover:border-outline-strong hover:text-foreground"
              >
                <Glyph className="h-3 w-3 text-ink-secondary" aria-hidden="true" />
                {ISSUE_TYPE_SHORT[issue]} {total}
              </ReportEvidenceLink>
            );
          })}
        </div>
      ) : null}
      </Collapsible>
    </div>
  );
}
