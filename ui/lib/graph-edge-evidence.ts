const categories: Record<string, string> = {
  static: "Static / configured", static_scan: "Static / configured",
  configured: "Static / configured", configured_target: "Static / configured", configured_delegation: "Static / configured",
  configuration: "Static / configured", recorded_configuration: "Static / configured",
  inferred: "Inferred", inferred_reachability: "Inferred",
  modeled: "Modeled", modeled_infrastructure: "Modeled",
  runtime_observed: "Runtime observed", runtime_blocked: "Runtime blocked",
};

// Collectors that read configuration or manifests rather than observing activity.
const STATIC_SOURCES = new Set(["source-ast", "cloud-inventory", "agent_discovery", "repo-structure-overlay"]);

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

// The edge evidence envelope: `tier` is the producer's own classification.
const tierLabels: Record<string, string> = {
  static_scan: "Static / configured",
  modeled_infrastructure: "Modeled", recorded: "Recorded observation",
  runtime_observed: "Runtime observed", derived: "Derived", legacy_unrecorded: "Not recorded",
};

function enveloped(evidence: Record<string, unknown>) {
  const tier = text(evidence.tier);
  if (!tier || !Object.hasOwn(tierLabels, tier)) return null;
  const blocked = evidence.runtime_observed_state === "blocked" || evidence.blocked === true;
  const label = blocked ? "Runtime blocked" : tierLabels[tier]!;
  const mode: "runtime" | "recorded" | "static" | "inferred" | "unknown" = blocked || tier === "runtime_observed" ? "runtime"
    : tier === "recorded" ? "recorded"
    : tier === "static_scan" ? "static"
    : tier === "modeled_infrastructure" || tier === "derived" ? "inferred" : "unknown";
  return { label, mode, blocked, source: text(evidence.source) };
}

/** Present explicit receipt markers; a verb or traversal flag is not evidence. */
export function graphEdgeEvidence(evidence: Record<string, unknown>) {
  // Prefer the recorded envelope; the heuristics below serve pre-envelope snapshots.
  const envelope = enveloped(evidence);
  if (envelope) return envelope;
  const labels = new Set<string>();
  for (const value of [evidence.evidence_tier, evidence.evidence_basis, evidence.basis]) {
    const key = text(value);
    if (key && Object.hasOwn(categories, key)) labels.add(categories[key]!);
  }
  const sources = [evidence.source, evidence.data_source];
  if (sources.some(source => typeof source === "string" && STATIC_SOURCES.has(source))) labels.add("Static / configured");
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
  return { label, mode, blocked, source: text(evidence.source) };

}

/** A scan-recorded link with no receipt keeps its snapshot origin instead of reading as unrecorded. */
export function graphEdgeEvidenceLabel(edge: { evidence?: Record<string, unknown> | undefined; source_scan_id?: string | null | undefined }): string {
  const { label } = graphEdgeEvidence(edge.evidence ?? {});
  return label === "Not recorded" && text(edge.source_scan_id) ? "Scan inventory · no per-edge receipt" : label;
}
