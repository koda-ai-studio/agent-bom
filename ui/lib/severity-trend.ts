export interface SeverityPoint {
  timestamp: string;
  critical: number;
  high: number;
}

export interface SeverityTrendResult {
  status: "none" | "single" | "series";
  points: (SeverityPoint & { time: number })[];
  criticalDelta: number;
  highDelta: number;
}

/** Critical and high counts per recorded snapshot, oldest first; undated points cannot be placed. */
export function severityTrend(points: SeverityPoint[]): SeverityTrendResult {
  const dated = points
    .map((point) => ({ ...point, time: Date.parse(point.timestamp) }))
    .filter((point) => Number.isFinite(point.time) && Number.isFinite(point.critical))
    .sort((a, b) => a.time - b.time);
  const first = dated[0];
  const last = dated.at(-1);
  return {
    status: dated.length === 0 ? "none" : dated.length === 1 ? "single" : "series",
    points: dated,
    criticalDelta: first && last ? last.critical - first.critical : 0,
    highDelta: first && last ? last.high - first.high : 0,
  };
}
