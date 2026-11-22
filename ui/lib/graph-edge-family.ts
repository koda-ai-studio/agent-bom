import { GRAPH_EDGE_KIND_META, type GraphEdgeKindKey } from "@/lib/graph-schema.generated";

/** Five line colours for the compact canvas, one per relationship family. */
export type EdgeFamily = "access" | "data" | "exposure" | "risk" | "structure";

const DATA = new Set(["stores", "accessed", "serves_model"]);
const ACCESS = new Set(["authenticates_as", "acted_as", "used_credential", "exposes_cred", "delegated_to"]);
const RISK = new Set(["exhibits_drift", "finding_group", "has_finding", "correlates_with", "possibly_correlates_with"]);

export function edgeFamily(relationship: string): EdgeFamily {
  if (DATA.has(relationship)) return "data";
  if (ACCESS.has(relationship)) return "access";
  if (RISK.has(relationship)) return "risk";
  const category = GRAPH_EDGE_KIND_META[relationship as GraphEdgeKindKey]?.category;
  if (category === "identity" || category === "lateral_movement") return "access";
  if (category === "exposure") return "exposure";
  if (category === "vulnerability" || category === "correlation") return "risk";
  return "structure";
}

export const edgeFamilyColor = (family: EdgeFamily) => `var(--graph-edge-${family})`;

/** Dashes mark modeled links, blocked links, and access not observed in use; recorded structure stays solid. */
export function edgeIsDashed(family: EdgeFamily, data: Record<string, unknown> | undefined): boolean {
  if (data?.evidenceBlocked === true || data?.evidenceMode === "inferred") return true;
  return family === "access" && data?.evidenceMode !== "runtime";
}
