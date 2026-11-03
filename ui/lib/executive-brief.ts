import type { components } from "./api-schema.generated";
import { nowForRelativeTime } from "./relative-clock";

export type ExecutiveBrief = components["schemas"]["ExecutiveBriefResponse"];
export type BriefVerificationKey = components["schemas"]["ComplianceVerificationKeyResponse"];
export const briefText = (value: unknown): string => value === null || value === undefined || value === "" ? "Not recorded" : typeof value === "object" ? JSON.stringify(value) : String(value);
const md = (value: unknown) => briefText(value).replace(/[\r\n]+/g, " ").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/[\\`*_{}\[\]()#+!|]/g, "\\$&");
export const pathLabel = (value: unknown) => value && typeof value === "object" && "label" in value ? briefText(value.label) : "Not recorded";

export type BriefPriority = ExecutiveBrief["remediation_priorities"][number];

const DAY_MS = 86_400_000;
const ABSOLUTE = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC", hour12: false });
const RELATIVE = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
const UNITS: [number, Intl.RelativeTimeFormatUnit][] = [[60_000, "minute"], [3_600_000, "hour"], [DAY_MS, "day"]];

/** "in 7 days · 8 Nov 2026, 18:32 UTC": relative for humans, absolute for the record, never microseconds. */
export function briefTimestamp(value: unknown, now = nowForRelativeTime()): string {
  if (typeof value !== "string" || !value.trim()) return "Not recorded";
  const parsed = Date.parse(value);
  // A recorded value that is not a date (a scan id) is shown as recorded, never hidden.
  if (!Number.isFinite(parsed)) return value;
  const delta = parsed - now;
  const [ms, unit] = UNITS.find(([size], i) => i === UNITS.length - 1 || Math.abs(delta / size) < (i === 0 ? 60 : 48))!;
  return `${RELATIVE.format(Math.round(delta / ms), unit)} · ${ABSOLUTE.format(parsed)} UTC`;
}

export type SlaTone = "danger" | "warning" | "ok" | "muted";
const CHIPS: Record<string, { label: string; tone: SlaTone }> = {
  overdue: { label: "Overdue", tone: "danger" },
  due_soon: { label: "Due soon", tone: "warning" },
  on_track: { label: "On track", tone: "ok" },
};

/** Chip from the API's ``sla_status`` when present, else derived from ``sla_due_at`` in whole days, as the API derives it. */
export function slaChipLabel(row: Pick<BriefPriority, "sla_due_at" | "sla_status">, now = nowForRelativeTime()): { label: string; tone: SlaTone } {
  let status = row.sla_status ?? "";
  if (!status) {
    const due = row.sla_due_at ? Date.parse(row.sla_due_at) : Number.NaN;
    status = !Number.isFinite(due) ? "unknown" : due < now ? "overdue" : Math.floor((due - now) / DAY_MS) <= 7 ? "due_soon" : "on_track";
  }
  return CHIPS[status] ?? { label: "No SLA", tone: "muted" };
}

const POLICY_LABELS: Record<string, string> = { "severity-kev/v1": "Severity and KEV policy (v1)", explicit: "Explicit due date", unknown: "Unattributed due date", unavailable: "No deadline derivable" };

/** Policy display name: the API's ``sla_policy`` when present, else the same table the API uses. */
export function slaPolicyLabel(row: Pick<BriefPriority, "sla_due_at_source" | "sla_policy">): string {
  const source = row.sla_due_at_source;
  return row.sla_policy || (source ? POLICY_LABELS[source] ?? source : "Not recorded");
}

const ADVISORY_ID = /^(CVE|GHSA|OSV|PYSEC|RUSTSEC|GO|MAL)-/i;

/** Advisory ids read as-is; other findings read by title, never by an internal id. */
export function briefFindingLabel(row: Pick<BriefPriority, "vulnerability_id" | "title">): string {
  return ADVISORY_ID.test(row.vulnerability_id) ? row.vulnerability_id : row.title || row.vulnerability_id || "Untitled finding";
}

/** The affected package, or the asset when the finding is not about a package. */
export function briefComponent(row: Pick<BriefPriority, "component" | "package">): string {
  return row.component || row.package || "—";
}

/** Better/worse from the newest comparable history point, worded as the CLI and reports word it. */
export function briefTrend(brief: Pick<ExecutiveBrief, "scan_history">): string {
  const comparison = brief.scan_history.data_points[0]?.comparison;
  if (!comparison || comparison.status !== "comparable") return `Trend: not comparable with the previous scan (${comparison?.reason ?? "no previous scan"}).`;
  const added = comparison.new_findings ?? 0;
  const resolved = comparison.no_longer_detected ?? 0;
  const head = added > resolved ? "Worse than the last scan" : resolved > added ? "Better than the last scan" : "Unchanged since the last scan";
  return `Trend: ${head}: ${added} newly detected, ${resolved} no longer detected.`;
}

export function briefFindingHref(row: ExecutiveBrief["remediation_priorities"][number]): string {
  const params = new URLSearchParams();
  if (row.canonical_id) params.set("finding", row.canonical_id);
  else params.set("q", row.vulnerability_id);
  return `/findings?${params}`;
}

export function briefMarkdown(brief: ExecutiveBrief): string {
  const { posture, issues, compliance, exposure_paths: paths } = brief;
  const lines = [
    `# Executive brief${brief.sample_data ? " — Sample data" : ""}`, "",
    `Tenant: ${md(brief.tenant_id)} · Generated: ${md(brief.generated_at)}`, "",
    "## Current posture", "", md(posture.summary),
    `Open issue groups: ${md(issues.total)} · Critical: ${md(issues.critical)} · High: ${md(issues.high)} · KEV: ${md(issues.kev)}`,
    "Counts are correlated issue groups, not finding occurrences.", md(briefTrend(brief)), "",
    "## Remediation priorities", "", "| Finding | Component | Owner | SLA | SLA due | Policy |", "|---|---|---|---|---|---|",
    ...brief.remediation_priorities.map(row => `| ${[briefFindingLabel(row), briefComponent(row), row.owner ?? "Unassigned", slaChipLabel(row).label, briefTimestamp(row.sla_due_at), slaPolicyLabel(row)].map(md).join(" | ")} |`),
  ];
  if (!brief.remediation_priorities.length) lines.push("No remediation priorities returned by the current overview.");
  lines.push("", "## Ranked exposure paths", "");
  if (brief.exposure_status === "unavailable" || !paths) lines.push("Path evidence unavailable; this does not establish that no exposure exists.");
  else {
    lines.push(`Snapshot: ${md(paths.scan_id)} · Generation: ${md(paths.snapshot_generation)}`);
    for (const row of paths.paths) lines.push(`- ${md(pathLabel(row.source))} → ${md(pathLabel(row.target))} · Severity: ${md(row.severity)} · Reachability: ${md(row.reachability)}`);
    if (!paths.paths.length) lines.push("No paths returned for this snapshot.");
    lines.push(`Collection coverage: ${md(paths.collection_coverage?.status)} · ${md(paths.collection_coverage?.reason)}`);
    lines.push(`Paths returned: ${md(paths.completeness?.returned)} of ${md(paths.completeness?.total)} · Completeness: ${md(paths.completeness?.status)} · ${md(paths.completeness?.reason)}`);
  }
  lines.push("", "## Technical control evidence", "", `Status: ${md(compliance.overall_status)} · Evaluated: ${md(compliance.evaluated_controls)}/${md(compliance.total_controls)} controls`, `Latest scan: ${md(compliance.latest_scan)}`);
  lines.push("", "| Framework | Passed | Warning | Failed | Not evaluated |", "|---|---|---|---|---|");
  for (const [name, counts] of Object.entries(compliance.frameworks)) if (counts.scored) lines.push(`| ${[name, counts.pass, counts.warning, counts.fail, counts.not_evaluated].map(md).join(" | ")} |`);
  lines.push("", "## Scope-specific scan history", "");
  for (const point of brief.scan_history.data_points) lines.push(`- Scan ${md(point.scan_id)} · ${md(point.timestamp)} · Comparison: ${md(point.comparison.status)} · Reason: ${md(point.comparison.reason)}`);
  if (!brief.scan_history.data_points.length) lines.push("No recorded scan history.");
  lines.push("", "## Evidence boundary", "", md(brief.evidence_boundary), "", "## Source scope", "", "```json", JSON.stringify(brief.scope, null, 2).replace(/`/g, "\\u0060"), "```", "", "The signed compliance pack is a separate artifact. Verify it with a trusted key and inspect its own scope.");
  return lines.join("\n") + "\n";
}

export function saveBriefArtifact(body: Blob, filename: string): void {
  const url = URL.createObjectURL(body);
  const anchor = document.createElement("a");
  anchor.href = url; anchor.download = filename;
  document.body.appendChild(anchor); anchor.click(); anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
