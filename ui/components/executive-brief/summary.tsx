import Link from "next/link";
import { ArrowUpRight, ShieldAlert } from "lucide-react";
import { type ExecutiveBrief, briefTimestamp, briefTrend } from "@/lib/executive-brief";

export function BriefSummary({ brief }: { brief: ExecutiveBrief }) {
  const { total, critical, high, kev } = brief.issues;
  const other = Math.max(0, total - critical - high);
  const metrics = [
    { label: "Critical groups", value: critical, color: "text-red-700 dark:text-red-300", href: "/findings?severity=critical" },
    { label: "High groups", value: high, color: "text-orange-700 dark:text-orange-300", href: "/findings?severity=high" },
    { label: "Known exploited", value: kev ?? "Unknown", color: "text-ink-primary", href: "/findings?kev=true" },
  ];
  return <section aria-label="Risk at a glance" className="overflow-hidden rounded-2xl border border-outline bg-surface">
    <div className="border-b border-outline px-5 py-4 sm:px-6">
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-ink-secondary">
        <span className={brief.sample_data ? "rounded-full border border-amber-500/50 bg-amber-500/10 px-2.5 py-1 text-amber-900 dark:text-amber-200" : "font-medium"}>{brief.sample_data ? "Sample data" : "Current tenant evidence"}</span>
        <span className="break-words">Tenant: {brief.tenant_id} · Generated: {briefTimestamp(brief.generated_at)}</span>
      </div>
      <h2 className="mt-4 flex items-start gap-2 text-xl font-semibold tracking-tight sm:text-2xl"><ShieldAlert className="mt-0.5 h-6 w-6 shrink-0 text-amber-700 dark:text-amber-300" aria-hidden="true" />{brief.posture.summary}</h2>
    </div>
    <div className="grid gap-6 p-5 sm:p-6 lg:grid-cols-[1fr_2fr]">
      <div>
        <p className="text-xs font-medium uppercase tracking-wider text-ink-secondary">Open issue groups</p>
        <p className="mt-2 text-6xl font-semibold tracking-tight tabular-nums">{total}</p>
        <div role="img" aria-label={`${critical} critical, ${high} high, ${other} other issue groups`} className="mt-4 flex h-2 overflow-hidden rounded-full bg-surface-muted">
          {[{ count: critical, color: "bg-red-500" }, { count: high, color: "bg-orange-400" }, { count: other, color: "bg-slate-400" }].map(({ count, color }, i) => <span key={i} className={color} style={{ width: `${total > 0 ? count / total * 100 : 0}%` }} />)}
        </div>
        <p className="mt-2 text-xs leading-5 text-ink-secondary">Correlated issue groups across the current tenant.</p>
      </div>
      <div className="grid grid-cols-3 divide-x divide-outline self-center">
        {metrics.map(metric => <Link key={metric.label} href={metric.href} className="group min-w-0 px-3 first:pl-0 last:pr-0 sm:px-5">
          <span className="flex items-start justify-between gap-1 text-xs leading-5 text-ink-secondary">{metric.label}<ArrowUpRight className="h-3.5 w-3.5 shrink-0" aria-hidden="true" /></span>
          <span className={`mt-2 block text-2xl font-semibold tabular-nums sm:text-4xl ${metric.color}`}>{metric.value}</span>
        </Link>)}
      </div>
    </div>
    <div className="space-y-2 border-t border-outline bg-surface-muted/40 px-5 py-4 text-sm sm:px-6">
      <p className="font-medium">{briefTrend(brief)}</p>
      {brief.posture.no_data ? <p>Posture evidence is incomplete. Returned issue counts do not establish complete coverage.</p> : null}
      {brief.posture.partial ? <p>Grade {brief.posture.grade_label}. Controls that errored or had no data are not assumed fine.</p> : null}
      <p className="text-xs leading-5 text-ink-secondary">{brief.evidence_boundary}</p>
    </div>
  </section>;
}
