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

/** One set of line weights for every graph renderer: a link at rest, one being inspected, and a selected path. */
export const EDGE_STROKE = { rest: 2.2, inspect: 2.8, path: 3.2 } as const;

/** Only modeled evidence is dashed; access verbs and neighbouring links do not change evidence. */
export function edgeIsDashed(_family: EdgeFamily, data: Record<string, unknown> | undefined): boolean {
  return data?.evidenceMode === "inferred";
}
