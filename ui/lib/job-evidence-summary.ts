import type { JobListItem } from "@/lib/api";

const metric = (value: number | null | undefined) => (value == null ? "Unavailable" : value.toLocaleString());

/** One line of a job's evidence totals, with thousands separators. */
export function jobEvidenceSummary(job: JobListItem): string {
  const summary = job.summary;
  if (!summary) return "Evidence metrics unavailable";
  const packages = `${metric(summary.total_packages)} packages`;
  if (typeof summary.total_findings === "number") {
    const critical = summary.critical_unified_findings;
    const criticalPart = typeof critical === "number" && critical <= summary.total_findings ? ` · ${critical.toLocaleString()} critical` : "";
    return `${summary.total_findings.toLocaleString()} findings${criticalPart} · ${packages}`;
  }
  // Legacy summaries: blast-radius criticals are only shown when they cannot
  // read as more criticals than the CVE total they sit beside.
  const vulns = summary.total_vulnerabilities;
  const critical = summary.critical_findings;
  const criticalPart = typeof critical === "number" && typeof vulns === "number" && critical <= vulns ? ` · ${critical.toLocaleString()} critical` : "";
  return `${metric(vulns)} CVEs${criticalPart} · ${packages}`;
}
