import { describe, expect, it } from "vitest";

import type { GraphRollupContainer } from "@/lib/api-types";
import {
  buildRollupFlowGraph,
  mergeReciprocalRollupEdges,
  rollupContainerSubtitle,
  rollupEntityToNodeType,
} from "@/lib/graph-rollup-view";

function sampleContainer(
  overrides: Partial<GraphRollupContainer> = {},
): GraphRollupContainer {
  return {
    id: "account:prod",
    label: "prod",
    entity_type: "account",
    severity: "",
    is_container: true,
    has_children: true,
    direct_child_count: 2,
    aggregate: {
      descendant_count: 42,
      by_type: { server: 2, package: 40 },
      severity_counts: { critical: 1, low: 39 },
      worst_severity: "critical",
      worst_severity_rank: 5,
      internet_exposed: true,
      toxic_combo: false,
      exposed_count: 1,
      toxic_count: 0,
    },
    ...overrides,
  };
}

describe("rollupEntityToNodeType", () => {
  it("maps estate entity types to lineage node types", () => {
    expect(rollupEntityToNodeType("account")).toBe("account");
    expect(rollupEntityToNodeType("application")).toBe("container");
    expect(rollupEntityToNodeType("unknown_type")).toBe("cloudResource");
  });
});

describe("rollupContainerSubtitle", () => {
  it("summarizes descendants, severity, exposure, and drill hint", () => {
    const subtitle = rollupContainerSubtitle(sampleContainer());
    expect(subtitle).toContain("42 descendants");
    expect(subtitle).toContain("worst critical");
    expect(subtitle).toContain("internet exposed");
    expect(subtitle).toContain("select to inspect scope");
  });

  it("tolerates missing aggregate without throwing", () => {
    const subtitle = rollupContainerSubtitle(
      sampleContainer({
        aggregate: undefined as unknown as GraphRollupContainer["aggregate"],
        direct_child_count: 2,
      }),
    );
    expect(subtitle).toContain("2 direct children");
    expect(subtitle).toContain("select to inspect scope");
  });
});

describe("buildRollupFlowGraph", () => {
  it.each(["directed", "bidirectional"] as const)("preserves %s direction on a homogeneous roll-up", direction => {
    const containers = [sampleContainer(), sampleContainer({ id: "account:dev" })];
    const { edges } = buildRollupFlowGraph(containers, { edges: [{ source: "account:prod", target: "account:dev", count: 2, relationships: ["uses"], directions: [direction], relationship_counts: { uses: 2 } }] });
    expect(edges[0]?.markerEnd).toBeDefined();
    if (direction === "bidirectional") expect(edges[0]?.markerStart).toEqual(edges[0]?.markerEnd);
    else expect(edges[0]?.markerStart).toBeUndefined();
    expect(edges[0]?.data?.aggregate).toMatchObject({ count: 2, directions: [direction] });
  });
  it("does not draw a single arrow for mixed or unavailable directions", () => {
    const containers = [sampleContainer(), sampleContainer({ id: "account:dev" })];
    for (const directions of [["directed", "bidirectional"], null, undefined]) {
      const { edges } = buildRollupFlowGraph(containers, { edges: [{ source: "account:prod", target: "account:dev", count: 3, relationships: ["uses"], ...(directions !== undefined ? { directions } : {}) }] });
      expect(edges[0]?.markerEnd).toBeUndefined();
      expect(edges[0]?.markerStart).toBeUndefined();
      expect(edges[0]?.animated).toBe(false);
    }
  });
  it("does not attribute a mixed aggregate count to the first relationship kind", () => {
    const containers = [sampleContainer(), sampleContainer({ id: "account:dev" })];
    const edges = [
      { source: "account:prod", target: "account:dev", count: 7, relationships: ["accessed", "assumes"] },
    ];
    const mixed = buildRollupFlowGraph(containers, { edges });
    expect(mixed.edges[0]?.label).toBe("7 relationships");
    const single = buildRollupFlowGraph(containers, { edges: [{ ...edges[0]!, relationships: ["accessed"] }] });
    expect(single.edges[0]?.label).toBe("7 relationships");
  });

  it("routes reverse-order links from facing card edges without crossing scope cards", () => {
    const { edges } = buildRollupFlowGraph([sampleContainer(), sampleContainer({ id: "account:dev" })], { edges: [{ source: "account:dev", target: "account:prod", count: 35, relationships: ["can_access", "uses"] }] });
    expect(edges[0]?.sourceHandle).toBe("scope-source-left");
    expect(edges[0]?.targetHandle).toBe("scope-target-right");
  });

  it("lays out containers on a grid with rollup metadata", () => {
    const { nodes, edges } = buildRollupFlowGraph([
      sampleContainer(),
      sampleContainer({
        id: "account:dev",
        label: "dev",
        has_children: false,
        aggregate: {
          ...sampleContainer().aggregate,
          descendant_count: 3,
          worst_severity: "low",
          worst_severity_rank: 1,
          internet_exposed: false,
        },
      }),
    ]);

    expect(edges).toHaveLength(0);
    expect(nodes).toHaveLength(2);
    expect(nodes[0]?.id).toBe("account:prod");
    expect(nodes[0]?.position).toEqual({ x: 0, y: 0 });
    expect(nodes[1]?.position).toEqual({ x: 440, y: 0 });
    expect(nodes[1]!.position.x - nodes[0]!.position.x).toBeGreaterThanOrEqual(300 + 32);
    expect(nodes[0]?.data.attributes?.rollup_has_children).toBe(true);
    expect(nodes[0]?.data.rollup).toEqual(sampleContainer());
    expect(nodes[0]?.data.description).toContain("select to inspect scope");
  });
});

describe("mergeReciprocalRollupEdges", () => {
  const forward = { source: "env:dev", target: "env:prod", count: 2, relationships: ["uses"], directions: ["directed"], relationship_counts: { uses: 2 } };
  const backward = { source: "env:prod", target: "env:dev", count: 1, relationships: ["accessed"], directions: ["directed"], relationship_counts: { accessed: 1 } };

  it("draws a reciprocal pair once so their labels cannot overlap", () => {
    const merged = mergeReciprocalRollupEdges([forward, backward]);
    expect(merged).toHaveLength(1);
    expect(merged[0]).toMatchObject({ source: "env:dev", target: "env:prod", count: 3, reverse: backward });
    expect(merged[0]?.relationships).toEqual(["uses", "accessed"]);
    expect(merged[0]?.relationship_counts).toEqual({ uses: 2, accessed: 1 });
  });

  it("keeps one-way links and unknown kind counts as they are", () => {
    expect(mergeReciprocalRollupEdges([forward])).toEqual([forward]);
    const merged = mergeReciprocalRollupEdges([forward, { ...backward, relationship_counts: null }]);
    expect(merged[0]?.relationship_counts).toBeNull();
  });

  it("marks both ends of a merged reciprocal link on the canvas", () => {
    const containers = [sampleContainer({ id: "env:dev" }), sampleContainer({ id: "env:prod" })];
    const { edges } = buildRollupFlowGraph(containers, { edges: mergeReciprocalRollupEdges([forward, backward]) });
    expect(edges).toHaveLength(1);
    expect(edges[0]?.label).toBe("3 relationships");
    expect(edges[0]?.markerStart).toEqual(edges[0]?.markerEnd);
  });
});
