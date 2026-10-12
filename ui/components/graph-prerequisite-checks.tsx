"use client";
import type { GraphConsequenceResponse } from "@/lib/api-types";
const names: Record<string, string> = {
  affected_inventory: "Advisory matches this component", recorded_version: "Version in inventory",
  required_entry_vector: "Required entry vector", required_complexity: "Required complexity",
  required_privileges: "Required privileges", required_interaction: "Required user interaction",
  deployed_configuration: "Deployed configuration", entry_point: "Reachable vulnerable entry point",
  local_exploitation: "Local exploitation prerequisites",
};
export function GraphPrerequisiteChecks({ checks }: { checks: NonNullable<GraphConsequenceResponse["prerequisites"]["checks"]> }) {
  if (!checks.length) return null;
  return <section className="rounded-xl border border-outline bg-surface p-5">
    <h3 className="text-sm font-semibold">Vulnerability prerequisites</h3>
    <p className="mt-2 text-xs text-ink-secondary">Advisory requirements describe the vulnerability. Local evidence must establish whether this deployment meets them.</p>
    <dl className="mt-4 divide-y divide-outline">{checks.map(check => <div key={check.name} className="flex flex-wrap items-center justify-between gap-2 py-3 text-sm">
      <dt>{names[check.name] ?? check.name.replaceAll("_", " ")}<span className="ml-2 text-xs text-ink-tertiary">{check.basis}</span></dt>
      <dd className={check.status === "recorded" ? "font-medium" : "text-amber-700 dark:text-amber-300"}>{check.value ?? (check.status === "recorded" ? "Recorded" : "Needs evidence")}</dd>
    </div>)}</dl>
  </section>;
}
