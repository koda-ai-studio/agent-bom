import { describe, expect, it } from "vitest";

import { accessEvidenceLegendItems } from "@/lib/graph-access-evidence";
import { createFocusedGraphFilters } from "@/components/lineage-filter";
import { EntityType, RelationshipType, type UnifiedGraphData, type UnifiedNode } from "@/lib/graph-schema";
import { legendItemsForVisibleGraph, relationshipEdgeLabelText } from "@/lib/graph-utils";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";

const at = "2026-06-01T00:00:00Z";

describe("configured versus observed access", () => {
  it.each([
    ["can_access", { evidenceMode: "inferred" }, "Can Access · modeled"],
    ["can_access", { evidenceMode: "runtime" }, "Can Access · observed"],
    ["can_access", { evidenceMode: "runtime", evidenceBlocked: true }, "Can Access · blocked"],
    ["uses", { evidenceMode: "static" }, "Uses · configured"],
    ["exposes_cred", { evidenceMode: "unknown" }, "Exposes Credential · evidence unspecified"],
    ["assumes", { evidenceMode: "static" }, "Assumes · configured"],
    ["depends_on", { evidenceMode: "static" }, "Depends On"],
    ["acted_as", { evidenceMode: "inferred" }, "Acted As · modeled"],
    ["called", { evidenceMode: "static" }, "Called · configured"],
    ["invoked", { evidenceMode: "unknown" }, "Invoked · evidence unspecified"],
    ["accessed", { evidenceMode: "runtime" }, "Accessed · observed"],
    ["used_credential", { evidenceMode: "runtime", evidenceBlocked: true }, "Used Credential · blocked"],
    ["delegated_to", { evidenceMode: "runtime", evidenceBlocked: true }, "Delegated To · blocked"],
    ["delegated_to", { evidenceMode: "static" }, "Configured delegation"],
    ["uses", undefined, "Uses"],
  ] as const)("labels %s with %j as %s", (relationship, metadata, label) => {
    expect(relationshipEdgeLabelText(relationship, metadata)).toBe(label);
  });

  it("dashes permitted access and keeps observed access solid, with a legend for both", () => {
    const node = (id: string, entityType: EntityType): UnifiedNode => ({
      id, entity_type: entityType, label: id, category_uid: 0, class_uid: 0, type_uid: 0, status: "active", risk_score: 0,
      severity: "none", severity_id: 0, first_seen: at, last_seen: at, attributes: {}, compliance_tags: [], data_sources: [], dimensions: {},
    });
    const edge = (id: string, source: string, target: string, evidence: Record<string, unknown>) => ({
      id, source, target, relationship: RelationshipType.CAN_ACCESS, direction: "directed", weight: 1, traversable: true,
      first_seen: at, last_seen: at, evidence, activity_id: 1,
    });
    const graph = {
      scan_id: "s", tenant_id: "default", created_at: at, attack_paths: [], interaction_risks: [],
      nodes: [node("cred", EntityType.CREDENTIAL), node("store", EntityType.DATA_STORE), node("store2", EntityType.DATA_STORE)],
      edges: [edge("permitted", "cred", "store", { tier: "modeled_infrastructure" }), edge("seen", "cred", "store2", { tier: "runtime_observed" })],
    } as unknown as UnifiedGraphData;
    const filters = createFocusedGraphFilters();
    const flow = buildUnifiedFlowGraph(graph, { ...filters, layers: { ...filters.layers, credential: true, dataStore: true } });
    const byId = new Map(flow.edges.map((item) => [item.id, item]));
    expect(byId.get("permitted")?.style?.strokeDasharray).toBeDefined();
    expect(byId.get("seen")?.style?.strokeDasharray).toBeUndefined();
    const legend = legendItemsForVisibleGraph(flow.nodes, flow.edges).map((item) => [item.label, item.lineStyle]);
    expect(legend).toEqual(expect.arrayContaining([["Configured / modeled", "dashed"], ["Observed at runtime", "solid"]]));
  });
});

 it("does not describe missing evidence or a blocked attempt as permitted access", () => {
   const legend = accessEvidenceLegendItems([
     { data: { relationship: "uses", evidenceMode: "unknown" } },
     { data: { relationship: "can_access", evidenceMode: "runtime", evidenceBlocked: true } },
   ]);
   expect(legend.map(item => item.label)).toEqual(["Blocked at runtime", "Evidence unspecified"]);
   expect(legend.every(item => item.dashed)).toBe(true);
 });
