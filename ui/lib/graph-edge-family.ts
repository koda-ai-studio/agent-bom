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
  if (data?.evidenceBlocked === true) return true;
  // When every drawn link is modeled the dash distinguishes nothing; the view states "Modeled" once instead.
  if (data?.uniformlyModeled === true) return false;
  if (data?.evidenceMode === "inferred") return true;
  return family === "access" && data?.evidenceMode !== "runtime";
}

/** Whether every edge would draw dashed for being modeled (none blocked), so a dash would carry no distinction. */
export function allEdgesModeled(edges: readonly { data?: Record<string, unknown> }[]): boolean {
  // Judged without the flag itself, so a second layout pass over already flagged edges reaches the same answer.
  return edges.length > 1 && edges.every(edge => edge.data?.evidenceBlocked !== true
    && edgeIsDashed(edgeFamily(String(edge.data?.relationship ?? "")), { ...edge.data, uniformlyModeled: false }));
}
