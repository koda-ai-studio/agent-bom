import { severityTrend, type SeverityPoint } from "@/lib/severity-trend";

const W = 1000;
const H = 100;

function change(delta: number): string {
  if (delta === 0) return "unchanged since the first snapshot";
  return `${Math.abs(delta)} ${delta < 0 ? "fewer" : "more"} than the first snapshot`;
}

/** Critical and high findings over the recorded snapshots; honest about a one-snapshot history. */
export function SeverityTrend({ points, headline }: { points: SeverityPoint[]; headline?: { critical: number; high: number } | null | undefined }) {
  const trend = severityTrend(points);
  if (trend.status === "none") return <p className="text-sm text-ink-secondary">No dated snapshots in this window.</p>;
  const latest = trend.points.at(-1)!;
  if (trend.status === "single") {
    return (
      <p className="text-sm text-ink-secondary">
        One snapshot so far ({new Date(latest.time).toLocaleDateString()}): <span className="font-semibold text-foreground">{latest.critical}</span> critical, {latest.high} high. A trend appears after the next scan.
      </p>
    );
  }
  const start = trend.points[0]!.time;
  const span = latest.time - start || 1;
  const max = Math.max(1, ...trend.points.map((point) => Math.max(point.critical, point.high)));
  const x = (time: number) => ((time - start) / span) * W;
  const y = (value: number) => H - (value / max) * (H - 4) - 2;
  const line = (key: "critical" | "high") => trend.points.map((point, index) => `${index ? "L" : "M"}${x(point.time).toFixed(1)} ${y(point[key]).toFixed(1)}`).join(" ");
  return (
    <figure className="min-w-0 rounded-xl border border-outline p-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <figcaption className="text-sm font-medium">Critical and high vulnerability occurrences in this scan scope</figcaption>
        <p className="text-xs text-ink-secondary">
          <span className="mr-1 text-lg font-semibold text-red-700 dark:text-red-300">{latest.critical}</span>
          critical now · {change(trend.criticalDelta)}
        </p>
      </div>
      <div className="mt-2 grid grid-cols-[auto_minmax(0,1fr)] gap-x-2">
        <div className="flex h-28 flex-col justify-between text-right text-xs tabular-nums text-ink-secondary"><span>{max}</span><span>0</span></div>
        <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img" aria-label={`Critical and high findings across ${trend.points.length} snapshots`}
          className="h-28 w-full border-b border-l border-outline">
          <title>{trend.points.map((point) => `${point.timestamp}: ${point.critical} critical, ${point.high} high`).join("; ")}</title>
          <path d={line("high")} fill="none" strokeWidth="2" vectorEffect="non-scaling-stroke" className="stroke-orange-600 dark:stroke-orange-300" />
          <path d={line("critical")} fill="none" strokeWidth="3" vectorEffect="non-scaling-stroke" className="stroke-red-700 dark:stroke-red-300" />
        </svg>
        <span />
        <div className="flex min-w-0 flex-wrap justify-between gap-x-2 pt-1 text-xs text-ink-secondary">
          <span>{new Date(start).toLocaleDateString()}</span>
          <span>{trend.points.length} snapshots</span>
          <span>{new Date(latest.time).toLocaleDateString()}</span>
        </div>
      </div>
      <p className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink-secondary">
        <span><span className="mr-1 inline-block h-0.5 w-4 bg-red-700 align-middle dark:bg-red-300" />Critical</span>
        <span><span className="mr-1 inline-block h-0.5 w-4 bg-orange-600 align-middle dark:bg-orange-300" />High · {latest.high} now, {change(trend.highDelta)}</span>
        <span>KEV counts are not recorded per snapshot, so KEV has no trend yet.</span>
      </p>
      {headline && (headline.critical !== latest.critical || headline.high !== latest.high) ? (
        <p className="mt-2 rounded-md border border-outline bg-surface-muted px-2 py-1.5 text-xs text-ink-secondary">
          Different basis: this chart counts vulnerability occurrences recorded by this scan scope ({latest.critical.toLocaleString()} critical). The posture headline counts {headline.critical.toLocaleString()} critical and {headline.high.toLocaleString()} high open issues across every surface, so the two are not expected to match.
        </p>
      ) : null}
    </figure>
  );
}
