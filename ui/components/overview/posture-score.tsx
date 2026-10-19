"use client";

import { Collapsible } from "@/components/collapsible";
import type {
ExecScoreDriver
} from "@/lib/api-types";
import type { SeverityCounts } from "@/lib/dashboard-data";
import { OverviewCockpitProps, PostureScoreFormat } from "./shared";

export function formatPostureScore(
  score: number | undefined,
  grade: string,
  format: PostureScoreFormat,
): string | null {
  if (typeof score !== "number") return null;
  const rounded = Math.round(score);
  switch (format) {
    case "grade":
      return `Grade ${grade}`;
    case "points":
      return `${rounded} / 100`;
    case "percent":
    default:
      return `${rounded}%`;
  }
}

export function derivePostureBlurb({
  summary,
  critical,
  high,
  severity,
  graded,
}: {
  summary?: string | undefined;
  critical: number;
  high: number;
  severity: SeverityCounts;
  graded: boolean;
}): string {
  if (!graded) return "Connect a surface or run a scan to grade posture.";
  const rated = severity.critical + severity.high + severity.medium + severity.low;
  const openIssues = Math.max(severity.total, rated);
  const unrated = openIssues - rated;

  if (openIssues > 0 || critical > 0 || high > 0) {
    const bits = [
      critical > 0 ? `${critical.toLocaleString("en-US")} critical` : null,
      high > 0 ? `${high.toLocaleString("en-US")} high` : null,
    ].filter(Boolean);
    const count = Math.max(openIssues, critical + high);
    const unratedNote = unrated > 0 ? ` (${unrated.toLocaleString("en-US")} without a severity)` : "";
    return `${count.toLocaleString("en-US")} open issue${count === 1 ? "" : "s"}${unratedNote}${bits.length ? ` · ${bits.join(" · ")}` : ""} across connected surfaces · same basis as the severity tiles.`;
  }

  // Nothing open: a backend summary can only be trusted here (it can't now
  // contradict the counts). Strip a trailing "(A, 95%)" that duplicates the
  // grade/score already shown beside it.
  const cleaned = summary?.replace(/\s*\([A-F][+-]?,\s*[\d.]+%\)\s*$/i, "").trim();
  return cleaned && cleaned.length > 0
    ? cleaned
    : "No open vulnerabilities across connected surfaces.";
}

export function ScoreExplainer({
  breakdown,
  grade,
  floored,
}: {
  floored?: boolean | undefined;
  breakdown?: ExecScoreDriver[] | null | undefined;
  grade: string;
}) {
  const ungraded = grade === "N/A" || grade === "—";
  const rows = (breakdown ?? [])
    .filter((row) => Number.isFinite(row.contribution) && row.contribution > 0 && Number.isFinite(row.count) && Number.isFinite(row.weight))
    .sort((a, b) => b.contribution - a.contribution);
  if (ungraded || rows.length === 0) return null;
  const totalPressure = rows.reduce((sum, row) => sum + row.contribution, 0);

  return (
    <Collapsible
      bare
      className="mt-4 border-t border-outline"
      title="What influences this score"
      titleClassName="text-sm font-medium text-foreground"
      defaultOpen={false}
      data-testid="overview-score-explainer"
    >
      <div className="mt-2 space-y-1.5">
        {rows.map((row) => {
          return (
            <div key={row.driver} className="space-y-1" data-testid={`score-driver-${row.driver}`}>
              <div className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-x-3 gap-y-0.5">
                <span className="min-w-0 text-xs leading-4 text-ink-secondary [overflow-wrap:anywhere]">
                  {row.label}
                </span>
                <span className="text-right font-mono text-xs font-semibold tabular-nums text-foreground">
                  {row.contribution.toFixed(1)}
                </span>
                <span className="col-span-2 font-mono text-xs tabular-nums text-ink-secondary">
                  {row.count} × {row.weight}
                </span>
              </div>
              <div className="h-1.5 overflow-hidden rounded-full bg-surface-muted" aria-hidden="true">
                <div
                  data-testid={`score-pressure-${row.driver}`}
                  className="h-full rounded-full bg-accent-mint"
                  style={{ width: `${(row.contribution / totalPressure) * 100}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
      <p className="mt-3 text-xs font-medium text-ink-secondary">Total weighted pressure: {totalPressure.toFixed(1)}</p>
      <p className="mt-2 text-xs leading-relaxed text-ink-secondary">
        Bars show each input’s share of weighted pressure (count × weight). The server converts combined pressure to a score using a nonlinear curve;
        these values are not points deducted from 100.
        {floored === true ? " The worse recorded scan posture limits the displayed score." : ""}
        {floored === undefined ? " Whether a recorded scan limits this score is unavailable." : ""}
      </p>
    </Collapsible>
  );
}

export const SCORE_FORMAT_OPTIONS: { value: PostureScoreFormat; label: string }[] = [
  { value: "grade", label: "Grade" },
  { value: "percent", label: "%" },
  { value: "points", label: "Points" },
];

export function ScoreFormatToggle({
  value,
  onChange,
}: {
  value: PostureScoreFormat;
  onChange: (format: PostureScoreFormat) => void;
}) {
  return (
    <div
      className="inline-flex overflow-hidden rounded-md border border-outline"
      role="group"
      aria-label="Score display format"
      data-testid="score-format-toggle"
    >
      {SCORE_FORMAT_OPTIONS.map((option) => {
        const active = option.value === value;
        return (
          <button
            key={option.value}
            type="button"
            onClick={() => onChange(option.value)}
            aria-pressed={active}
            className={`px-2 py-1 text-xs font-semibold transition ${
              active
                ? "bg-surface-elevated text-foreground"
                : "bg-surface-muted text-ink-secondary hover:text-foreground"
            }`}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}

export function PostureHero({
  localReport = false,
  loading,
  grade,
  score,
  scoreFormat = "percent",
  onScoreFormatChange,
  summary,
  trend,
  critical,
  high,
  severity,
}: {
  localReport?: boolean | undefined;
  loading: boolean;
  grade: string;
  score?: number | undefined;
  scoreFormat?: PostureScoreFormat | undefined;
  onScoreFormatChange?: ((format: PostureScoreFormat) => void) | undefined;
  summary?: string | undefined;
  trend?: OverviewCockpitProps["postureTrend"];
  critical: number;
  high: number;
  severity: SeverityCounts;
}) {
  const ungraded = grade === "N/A" || grade === "—";
  const graded = !loading && typeof score === "number" && !ungraded;
  const scoreDisplay = graded ? formatPostureScore(score, grade, scoreFormat) : null;
  const scoreTone = graded && ["D", "F"].includes(grade)
    ? "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300"
    : graded && grade === "C"
      ? "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-200"
      : "border-outline-strong bg-surface-muted text-foreground";
  const blurb = loading
    ? "Refreshing the current posture and evidence summary."
    : localReport ? "Tenant posture cannot be assessed from an imported report. Review its findings below." : derivePostureBlurb({ summary, critical, high, severity, graded });

  return (
    <div className="flex items-center gap-4">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-ink-secondary">
            Risk posture
          </p>
          {graded && onScoreFormatChange ? (
            <ScoreFormatToggle value={scoreFormat} onChange={onScoreFormatChange} />
          ) : null}
        </div>
        <p className={`mt-2 inline-flex flex-wrap items-baseline gap-3 rounded-xl border px-3 py-2 font-semibold ${scoreTone}`} data-testid="overview-posture-score">
          {loading ? (
            "Loading posture…"
          ) : graded ? (
            <>
              {/* Always show BOTH the letter grade and the %/points, whatever the
                  chosen primary format, so the number is never ambiguous. */}
              <span className="text-4xl leading-none tracking-tight tabular-nums">{scoreDisplay}</span>
              {scoreFormat !== "grade" ? (
                <span className="text-xs font-medium text-ink-secondary">Grade {grade}</span>
              ) : typeof score === "number" ? (
                <span className="text-xs font-medium text-ink-secondary">{Math.round(score)}%</span>
              ) : null}
            </>
          ) : (
            localReport ? "Posture unavailable" : "Awaiting scan"
          )}
        </p>
        {graded && <p className="mt-2 text-sm font-medium text-foreground">Posture score · 0–100, higher is better</p>}
        {graded ? (
          trend && trend.points >= 2 ? (
            <p
              className="mt-1 text-xs text-ink-secondary"
              data-testid="overview-posture-trend"
              title={`Previous posture score: ${Math.round(trend.previousScore)}%`}
            >
              {trend.direction === "unchanged"
                ? "Unchanged since the previous scan"
                : `${trend.direction === "improved" ? "Improved" : "Worsened"} ${Math.abs(Math.round(trend.delta))} points since the previous scan`}
            </p>
          ) : (
            <p className="mt-1 text-xs text-ink-secondary">
              Current evidence snapshot · use Top risks to prioritize remediation
            </p>
          )
        ) : null}
        <p className="mt-2 text-sm leading-relaxed text-ink-secondary">{blurb}</p>
      </div>
    </div>
  );
}
