import Link from "next/link";
import { Card } from "@/components/card";
import { type ExecutiveBrief, type SlaTone, briefFindingHref, briefText, briefTimestamp, pathLabel, slaChipLabel, slaPolicyLabel } from "@/lib/executive-brief";

const SLA_TONE_CLASS: Record<SlaTone, string> = {
  danger: "border-[color:var(--status-danger)] text-[color:var(--status-danger)]",
  warning: "border-[color:var(--status-warning)] text-[color:var(--status-warning)]",
  ok: "border-[color:var(--status-success)] text-[color:var(--status-success)]",
  muted: "border-outline text-ink-tertiary",
};

export function SlaChip({ row }: { row: ExecutiveBrief["remediation_priorities"][number] }) {
  const chip = slaChipLabel(row);
  return <span className={`inline-flex shrink-0 items-center rounded-full border px-2 py-0.5 text-xs font-medium ${SLA_TONE_CLASS[chip.tone]}`}>{chip.label}</span>;
}

export function BriefPriorities({ brief }: { brief: ExecutiveBrief }) {
  return <Card className="space-y-3">
    <div className="flex flex-wrap justify-between gap-2"><h2 className="text-lg font-semibold">Remediation priorities</h2><Link className="text-sm underline" href="/remediation">Open remediation</Link></div>
    <p className="text-sm text-ink-secondary">Canonical overview priorities. Owner and SLA remain attached to each finding occurrence.</p>
    <ul className="divide-y divide-outline">{brief.remediation_priorities.map((row, i) => <li key={`${row.canonical_id ?? row.vulnerability_id}-${i}`} className="space-y-1.5 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <Link href={briefFindingHref(row)} className="break-words font-medium underline">{row.vulnerability_id} · {row.package ?? "Package not recorded"}</Link>
        <SlaChip row={row} />
      </div>
      <p className="break-words text-sm text-ink-secondary">{row.severity} · Owner: {row.owner ?? "Not recorded"}</p>
      <p className="break-words text-xs text-ink-tertiary">SLA due {briefTimestamp(row.sla_due_at)} · Policy: {slaPolicyLabel(row)}</p>
    </li>)}</ul>
    {!brief.remediation_priorities.length ? <p className="text-sm text-ink-secondary">No remediation priorities returned by the current overview.</p> : null}
  </Card>;
}

export function BriefPaths({ brief }: { brief: ExecutiveBrief }) {
  const paths = brief.exposure_paths;
  const available = brief.exposure_status === "available" && paths;
  return <Card className="space-y-3">
    <h2 className="text-lg font-semibold">Ranked exposure paths</h2>
    {!available ? <p className="text-sm text-ink-secondary">Path evidence unavailable; this does not establish that no exposure exists.</p> : <>
      <p className="break-words text-sm text-ink-secondary">Snapshot: {briefText(paths.scan_id)} · Generation: {briefText(paths.snapshot_generation)}</p>
      <ul className="space-y-3">{paths.paths.map((row, i) => <li key={i} className="text-sm">
        <p className="break-words font-medium">{pathLabel(row.source)} → {pathLabel(row.target)}</p>
        <p className="text-ink-secondary">Severity: {briefText(row.severity)} · Reachability: {briefText(row.reachability)}</p>
      </li>)}</ul>
      {!paths.paths.length ? <p className="text-sm">No paths returned for this snapshot.</p> : null}
      <p className="text-sm text-ink-secondary">Collection coverage: {briefText(paths.collection_coverage?.status)} · {briefText(paths.collection_coverage?.reason)}</p>
      <p className="text-sm text-ink-secondary">Returned {briefText(paths.completeness?.returned)} of {briefText(paths.completeness?.total)} · {briefText(paths.completeness?.status)} · {briefText(paths.completeness?.reason)}</p>
      {paths.scan_id ? <Link className="inline-block text-sm underline" href={`/security-graph?${new URLSearchParams({ scan: paths.scan_id, lens: "attack-path" })}`}>Investigate this snapshot</Link> : null}
    </>}
  </Card>;
}

export function BriefControlsAndHistory({ brief }: { brief: ExecutiveBrief }) {
  const { compliance, scan_history: history } = brief;
  return <div className="grid gap-4 lg:grid-cols-2">
    <Card className="min-w-0 space-y-3">
      <h2 className="text-lg font-semibold">Technical control evidence</h2>
      <p className="text-sm">{compliance.overall_status} · {compliance.evaluated_controls} of {compliance.total_controls} controls evaluated</p>
      <p className="break-words text-sm text-ink-secondary">Latest scan: {briefTimestamp(compliance.latest_scan)}</p>
      <p className="text-sm text-ink-secondary">Technical results do not establish framework attestation. Inspect the control evidence and applicability.</p>
      <Link href="/compliance" className="inline-block text-sm underline">Review control evidence</Link>
    </Card>
    <Card className="min-w-0 space-y-3">
      <h2 className="text-lg font-semibold">Scope-specific scan history</h2>
      <p className="text-sm text-ink-secondary">These comparisons retain their own scope. They are not deltas against the tenant-wide posture score.</p>
      <ul className="space-y-3">{history.data_points.map((point, i) => <li key={`${point.scan_id}-${i}`} className="break-words text-sm">
        {point.scan_id ? <Link href={`/findings?${new URLSearchParams({ scan: point.scan_id })}`} className="underline">Scan {point.scan_id}</Link> : "Scan not recorded"}
        <p className="text-ink-secondary">{briefTimestamp(point.timestamp)} · {point.comparison.status} · {briefText(point.comparison.reason)}</p>
      </li>)}</ul>
      {!history.data_points.length ? <p className="text-sm">No recorded scan history.</p> : null}
    </Card>
  </div>;
}
