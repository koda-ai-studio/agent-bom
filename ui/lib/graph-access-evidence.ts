import type { LegendItem } from "@/lib/graph-utils";

/** Relationships whose consequence depends on whether access was configured or actually used. */
export const CONSEQUENTIAL_RELATIONSHIPS: ReadonlySet<string> = new Set([
  "can_access", "has_permission", "uses", "exposes_cred", "assumes", "authenticates_as",
  "acted_as", "called", "invoked", "accessed", "used_credential", "delegated_to",
]);

type EvidenceMetadata = { evidenceMode?: unknown; evidenceBlocked?: unknown } | undefined;

/** Short canvas qualifier from the recorded evidence tier; never derived from the verb. */
export function accessEvidenceQualifier(relationship: string, metadata: EvidenceMetadata): string | undefined {
  if (!CONSEQUENTIAL_RELATIONSHIPS.has(relationship) || !metadata || metadata.evidenceMode === undefined) return undefined;
  if (metadata.evidenceMode === "runtime") return metadata.evidenceBlocked === true ? "blocked" : "observed";
  if (metadata.evidenceMode === "recorded") return "recorded";
  if (metadata.evidenceMode === "static") return "configured";
  if (metadata.evidenceMode === "inferred") return "modeled";
  return "evidence unspecified";
}

/** Only non-blocked runtime receipts draw solid; dashed links do not establish permission or success. */
export function isObservedAccess(relationship: string, metadata: EvidenceMetadata): boolean {
  return accessEvidenceQualifier(relationship, metadata) === "observed";
}

export function accessEvidenceLegendItems(edges: Array<{ data?: unknown }>): LegendItem[] {
  const qualifiers = new Set(edges.flatMap(edge => {
    const data = edge.data as ({ relationship?: unknown } & NonNullable<EvidenceMetadata>) | undefined;
    const qualifier = typeof data?.relationship === "string" ? accessEvidenceQualifier(data.relationship, data) : undefined;
    return qualifier ? [qualifier] : [];
  }));
  const color = "#94a3b8";
  const item = (label: string, description: string, observed = false): LegendItem => ({
    label, description, color, kind: "edge", dashed: !observed, lineStyle: observed ? "solid" : "dashed",
  });
  return [
    ...(qualifiers.has("configured") || qualifiers.has("modeled") ? [item("Configured / modeled",
      "Links read from configuration or modeled infrastructure. Runtime use and effective permission are not established.")] : []),
    ...(qualifiers.has("observed") ? [item("Observed at runtime",
      "Access or use backed by a recorded runtime receipt. Inspect the receipt for its outcome.", true)] : []),
    ...(qualifiers.has("recorded") ? [item("Recorded observation",
      "A collector recorded this relationship. A runtime activity receipt is not established.")] : []),
    ...(qualifiers.has("blocked") ? [item("Blocked at runtime",
      "A runtime receipt records a blocked attempt; successful access is not established.")] : []),
    ...(qualifiers.has("evidence unspecified") ? [item("Evidence unspecified",
      "The link has no recognized evidence classification. Inspect its source and receipt; configuration and runtime use are not established.")] : []),
  ];
}
