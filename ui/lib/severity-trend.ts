export interface SeverityPoint {
  timestamp: string;
  critical: number;
  high: number;
  /** Open issue groups the posture headline counted when the point was recorded; absent on older points. */
  issues?: { critical: number; high: number } | null | undefined;
}

export type TrendBasis = "issues" | "occurrences";

export interface SeverityTrendResult {
  status: "none" | "single" | "series";
  /** Issues only when every dated point recorded them, so one line never mixes units. */
  basis: TrendBasis;
  points: (SeverityPoint & { time: number })[];
  /** The latest point's vulnerability occurrences, kept beside an issue-basis line under their own label. */
  latestOccurrences: { critical: number; high: number } | null;
  criticalDelta: number;
  highDelta: number;
}

/** Critical and high counts per recorded snapshot, oldest first; undated points cannot be placed. */
export function severityTrend(points: SeverityPoint[]): SeverityTrendResult {
  const dated = points
    .map((point) => ({ ...point, time: Date.parse(point.timestamp) }))
    .filter((point) => Number.isFinite(point.time) && Number.isFinite(point.critical))
    .sort((a, b) => a.time - b.time);
  const basis: TrendBasis = dated.length > 0 && dated.every((point) => point.issues && Number.isFinite(point.issues.critical)) ? "issues" : "occurrences";
  const plotted = basis === "issues" ? dated.map((point) => ({ ...point, critical: point.issues!.critical, high: point.issues!.high })) : dated;
  const first = plotted[0];
  const last = plotted.at(-1);
  const rawLast = dated.at(-1);
  return {
    status: plotted.length === 0 ? "none" : plotted.length === 1 ? "single" : "series",
    basis,
    points: plotted,
    latestOccurrences: basis === "issues" && rawLast ? { critical: rawLast.critical, high: rawLast.high } : null,
    criticalDelta: first && last ? last.critical - first.critical : 0,
    highDelta: first && last ? last.high - first.high : 0,
  };
}
