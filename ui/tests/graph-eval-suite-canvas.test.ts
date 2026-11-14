import { describe, expect, it } from "vitest";

import { EXPANDED_LAYER_DEFAULTS } from "@/components/lineage-filter";
import { assetKind, ASSET_KINDS } from "@/lib/asset-icon-registry";
import { lineageNodeTypeForEntity } from "@/lib/graph-entity-mapping";
import { EntityType, RelationshipType, type UnifiedGraphData, type UnifiedNode } from "@/lib/graph-schema";
import { relationshipLegendItem, relationshipLegendItemsForVisibleEdges } from "@/lib/graph-utils";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";

function node(id: string, entityType: EntityType, label: string, attributes: Record<string, unknown> = {}): UnifiedNode {
  return {
    id, entity_type: entityType, label, category_uid: 5, class_uid: 4001, type_uid: 400101, status: "active",
    risk_score: 0, severity: "none", severity_id: 0, first_seen: "2026-11-01T00:00:00Z", last_seen: "2026-11-01T00:00:00Z",
    attributes, compliance_tags: [], data_sources: [], dimensions: {} as UnifiedNode["dimensions"],
  };
}

const suite = node("eval_suite:redteam", EntityType.EVAL_SUITE, "redteam suite", {
  harness: "promptfoo", purpose: "safety", file_path: "evals/promptfooconfig.yaml", executed: false,
});
const agent = node("agent:support", EntityType.AGENT, "support-agent");

const graph: UnifiedGraphData = {
  scan_id: "eval-suite", tenant_id: "default", created_at: "2026-11-01T00:00:00Z",
  nodes: [suite, agent],
  edges: [{
    id: "eval_suite:redteam:evaluates:agent:support", source: suite.id, target: agent.id,
    relationship: RelationshipType.EVALUATES, direction: "directed", weight: 1, traversable: false,
    first_seen: "2026-11-01T00:00:00Z", last_seen: "2026-11-01T00:00:00Z", evidence: {}, activity_id: 1,
  }],
  attack_paths: [], interaction_risks: [],
  stats: {
    total_nodes: 2, total_edges: 1, node_types: {}, severity_counts: {}, relationship_types: {},
    attack_path_count: 0, interaction_risk_count: 0, max_attack_path_risk: 0, highest_interaction_risk: 0,
  },
};

describe("eval suite on the canvas", () => {
  it("renders the suite as its own lineage type with harness and purpose as the subtitle", () => {
    const flow = buildUnifiedFlowGraph(graph, {
      layers: { ...EXPANDED_LAYER_DEFAULTS }, severity: null, agentName: null, vulnOnly: false, maxDepth: 3,
    });
    const rendered = flow.nodes.find((entry) => entry.id === suite.id);
    expect(lineageNodeTypeForEntity(EntityType.EVAL_SUITE)).toBe("evalSuite");
    expect(rendered?.type).toBe("evalSuiteNode");
    expect(rendered?.data.nodeType).toBe("evalSuite");
    expect(rendered?.data.description).toBe("promptfoo · safety");
    expect(flow.edges.map((entry) => entry.data?.relationship)).toEqual(["evaluates"]);
  });

  it("falls back to the file path when harness and purpose are missing", () => {
    const bare = { ...graph, nodes: [node(suite.id, EntityType.EVAL_SUITE, "bare", { file_path: "evals/x.yaml" }), agent] };
    const flow = buildUnifiedFlowGraph(bare, {
      layers: { ...EXPANDED_LAYER_DEFAULTS }, severity: null, agentName: null, vulnOnly: false, maxDepth: 3,
    });
    expect(flow.nodes.find((entry) => entry.id === suite.id)?.data.description).toBe("evals/x.yaml");
  });

  it("uses one eval-suite glyph for both the backend and lineage spellings", () => {
    expect(assetKind({ entityType: "eval_suite" })).toBe("eval_suite");
    expect(assetKind({ nodeType: "evalSuite" })).toBe("eval_suite");
    expect(ASSET_KINDS.eval_suite.label).toBe("Eval suite");
  });

  it("explains the evaluates edge honestly in the legend", () => {
    const item = relationshipLegendItem("evaluates");
    expect(item.label).toBe("Evaluates");
    expect(item.description).toMatch(/^Eval suite tests this agent or model/);
    expect(item.description).toContain("not run");
    expect(relationshipLegendItemsForVisibleEdges([{ data: { relationship: "evaluates" } }]).map((row) => row.label)).toEqual(["Evaluates"]);
  });
});
