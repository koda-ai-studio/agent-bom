const categories: Record<string, string> = {
  static: "Static / configured", static_scan: "Static / configured", static_evidence: "Static / configured",
  configured: "Static / configured", configured_target: "Static / configured", configured_delegation: "Static / configured",
  configuration: "Static / configured", recorded_configuration: "Static / configured",
  inferred: "Inferred", inferred_reachability: "Inferred",
  modeled: "Modeled", modeled_infrastructure: "Modeled",
  runtime_observed: "Runtime observed", runtime_blocked: "Runtime blocked",
};

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

/** Present explicit receipt markers; a verb or traversal flag is not evidence. */
export function graphEdgeEvidence(evidence: Record<string, unknown>) {
  const labels = new Set<string>();
  for (const value of [evidence.evidence_tier, evidence.evidence_basis, evidence.basis]) {
    const key = text(value);
    if (key && Object.hasOwn(categories, key)) labels.add(categories[key]!);
  }
  const sources = [evidence.source, evidence.data_source];
  if (sources.some(source => source === "source-ast" || source === "cloud-inventory")) labels.add("Static / configured");
  if (sources.includes("cloud-audit-trail") && evidence.observed === true) labels.add("Cloud audit observation");
  if (evidence.runtime_observed_state === "blocked" || evidence.blocked === true) labels.add("Runtime blocked");
  const runtimeSource = sources.some(source => typeof source === "string" && ["runtime-proxy", "runtime-identity", "runtime-feedback"].includes(source));
  if (runtimeSource && !labels.has("Runtime observed") && !labels.has("Runtime blocked")) labels.add("Runtime receipt");
  const blocked = labels.has("Runtime blocked");
  if (blocked) { labels.delete("Runtime observed"); labels.delete("Runtime receipt"); }
  const unclassified = [evidence.evidence_tier, evidence.evidence_basis, evidence.basis].some(value => text(value));
  const label = labels.size > 1 ? "Mixed recorded evidence" : [...labels][0] ?? (unclassified ? "Unclassified" : "Not recorded");
  const mode: "runtime" | "static" | "inferred" | "unknown" = labels.size !== 1 ? "unknown"
    : label === "Static / configured" ? "static"
    : label === "Inferred" || label === "Modeled" ? "inferred"
    : ["Runtime observed", "Runtime blocked", "Runtime receipt", "Cloud audit observation"].includes(label) ? "runtime" : "unknown";
  return { label, mode, blocked };

}
