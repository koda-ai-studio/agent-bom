import { describe, expect, it } from "vitest";

import { formatGraphHeadline } from "@/lib/graph-headline";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { createFocusedGraphFilters } from "@/components/lineage-filter";
import { EntityType, RelationshipType, type UnifiedGraphData, type UnifiedNode } from "@/lib/graph-schema";

const at = "2026-06-01T00:00:00Z";

function node(id: string, entityType: EntityType, severity: string, attributes: Record<string, unknown> = {}, risk = 0): UnifiedNode {
  return {
    id, entity_type: entityType, label: id, category_uid: 0, class_uid: 0, type_uid: 0, status: "active",
    risk_score: risk, severity, severity_id: 0, first_seen: at, last_seen: at, attributes,
    compliance_tags: [], data_sources: ["test"], dimensions: {},
  };
}

function graph(nodes: UnifiedNode[], paths = 1): UnifiedGraphData {
  return {
    scan_id: "s", tenant_id: "default", created_at: at, nodes,
    edges: [{
      id: "e", source: nodes[0]!.id, target: nodes[1]!.id, relationship: RelationshipType.VULNERABLE_TO,
      direction: "directed", weight: 1, traversable: true, first_seen: at, last_seen: at, evidence: {}, activity_id: 1,
    }],
    attack_paths: Array.from({ length: paths }, () => ({
      source: nodes[0]!.id, target: nodes[1]!.id, hops: [nodes[0]!.id, nodes[1]!.id], edges: [], composite_risk: 9,
      summary: "", credential_exposure: [], tool_exposure: [], vuln_ids: [],
    })),
    interaction_risks: [],
  } as unknown as UnifiedGraphData;
}

describe("graph headline counts", () => {
  it("does not count a high-severity KEV advisory as critical", () => {
    const flow = buildUnifiedFlowGraph(graph([
      node("pkg", EntityType.PACKAGE, "none"),
      node("cve", EntityType.VULNERABILITY, "high", { is_kev: true }, 9.1),
    ]), createFocusedGraphFilters());
    expect(flow.summary.findingSeverity).toMatchObject({ critical: 0, high: 1 });
    expect(flow.summary.critical).toBe(0);
    expect(flow.summary.kevListed).toBe(1);
    expect(formatGraphHeadline(flow.summary, 1)).toBe("1 high finding · 1 KEV-listed · 1 snapshot path");
  });

  it("breaks mixed severities out separately from KEV status", () => {
    const flow = buildUnifiedFlowGraph(graph([
      node("pkg", EntityType.PACKAGE, "none"),
      node("cve-a", EntityType.VULNERABILITY, "high", { is_kev: true }),
      node("cve-b", EntityType.VULNERABILITY, "critical"),
      node("misconfig", EntityType.MISCONFIGURATION, "medium"),
    ]), createFocusedGraphFilters());
    expect(formatGraphHeadline(flow.summary, 3)).toBe(
      "3 findings: 1 critical, 1 high, 1 medium · 1 KEV-listed · 3 snapshot paths",
    );
  });

  it("states zero findings without inventing a severity", () => {
    expect(formatGraphHeadline({ findings: 0, findingSeverity: { critical: 0, high: 0, medium: 0, low: 0, unrated: 0 }, kevListed: 0 }, 0))
      .toBe("0 findings · 0 snapshot paths");
  });

  it("names unrated findings rather than folding them into a severity", () => {
    expect(formatGraphHeadline({ findings: 2, findingSeverity: { critical: 0, high: 1, medium: 0, low: 0, unrated: 1 }, kevListed: 0 }, 1))
      .toBe("2 findings: 1 high, 1 unrated · 1 snapshot path");
  });
});
