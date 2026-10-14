import type { LegendItem } from "@/lib/graph-utils";

/** Relationships whose consequence depends on whether access was configured or actually used. */
export const CONSEQUENTIAL_RELATIONSHIPS: ReadonlySet<string> = new Set([
  "can_access", "has_permission", "uses", "exposes_cred", "assumes", "authenticates_as",
]);

type EvidenceMetadata = { evidenceMode?: unknown; evidenceBlocked?: unknown } | undefined;

/** Short canvas qualifier from the recorded evidence tier; never derived from the verb. */
export function accessEvidenceQualifier(relationship: string, metadata: EvidenceMetadata): string | undefined {
  if (!CONSEQUENTIAL_RELATIONSHIPS.has(relationship) || !metadata || metadata.evidenceMode === undefined) return undefined;
  if (metadata.evidenceMode === "runtime") return metadata.evidenceBlocked === true ? "blocked" : "observed";
  if (metadata.evidenceMode === "static") return "configured";
  if (metadata.evidenceMode === "inferred") return "modeled";
  return "not verified";
}

/** Observed (non-blocked) runtime access draws solid; everything else is permission, drawn dashed. */
export function isObservedAccess(relationship: string, metadata: EvidenceMetadata): boolean {
  return accessEvidenceQualifier(relationship, metadata) === "observed";
}

export function accessEvidenceLegendItems(edges: Array<{ data?: unknown }>): LegendItem[] {
  let permitted = false, observed = false;
  for (const edge of edges) {
    const data = edge.data as ({ relationship?: unknown } & NonNullable<EvidenceMetadata>) | undefined;
    if (typeof data?.relationship !== "string" || !accessEvidenceQualifier(data.relationship, data)) continue;
    if (isObservedAccess(data.relationship, data)) observed = true;
    else permitted = true;
  }
  const color = "#94a3b8";
  return [
    ...(permitted ? [{ label: "Permitted · not observed", color, kind: "edge" as const, dashed: true, lineStyle: "dashed" as const,
      description: "Access, use or credential links read from configuration or modeled infrastructure. Not observed at runtime." }] : []),
    ...(observed ? [{ label: "Observed at runtime", color, kind: "edge" as const, dashed: false, lineStyle: "solid" as const,
      description: "Access or use backed by a recorded runtime receipt." }] : []),
  ];
}
