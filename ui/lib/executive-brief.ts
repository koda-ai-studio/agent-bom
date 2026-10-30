import type { components } from "./api-schema.generated";

export type ExecutiveBrief = components["schemas"]["ExecutiveBriefResponse"];
export type BriefVerificationKey = components["schemas"]["ComplianceVerificationKeyResponse"];
export const briefText = (value: unknown): string => value === null || value === undefined || value === "" ? "Not recorded" : typeof value === "object" ? JSON.stringify(value) : String(value);
const md = (value: unknown) => briefText(value).replace(/[\r\n]+/g, " ").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/[\\`*_{}\[\]()#+!|]/g, "\\$&");
export const pathLabel = (value: unknown) => value && typeof value === "object" && "label" in value ? briefText(value.label) : "Not recorded";

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
    `Open issues: ${md(issues.total)} · Critical: ${md(issues.critical)} · High: ${md(issues.high)} · KEV: ${md(issues.kev)}`, "",
    "## Remediation priorities", "", "| Finding | Package | Owner | SLA due | SLA source |", "|---|---|---|---|---|",
    ...brief.remediation_priorities.map(row => `| ${[row.vulnerability_id, row.package, row.owner, row.sla_due_at, row.sla_due_at_source].map(md).join(" | ")} |`),
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
