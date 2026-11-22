import { SEMANTIC_COLUMN_GAP, SEMANTIC_ROW_GAP } from "@/lib/graph-semantic-layout";
/** Roll-up windows stay bounded while their columns retain backend meaning. */
import { describe, expect, it } from "vitest";
import type { GraphRollupContainer } from "@/lib/api-types";
import { buildRollupFlowGraph } from "@/lib/graph-rollup-view";
import { graphConnectionPreview } from "@/lib/graph-connection-preview";

function containers(count: number): GraphRollupContainer[] {
  return Array.from({ length: count }, (_, index) => ({
    id: `account:acct-${index}`,
    label: `acct-${index}`,
    entity_type: "account",
    semantic_layer: "infra",
    severity: "",
    is_container: true,
    has_children: true,
    direct_child_count: 4,
    aggregate: {
      descendant_count: 40,
      by_type: { resource: 40 },
      severity_counts: { high: 7 },
      worst_severity: "high",
      worst_severity_rank: 3,
      internet_exposed: false,
      toxic_combo: false,
      exposed_count: 0,
      toxic_count: 0,
    },
  }));
}

describe("bounded semantic roll-up windows", () => {
  it("opens six real scopes from the 106-container estate without shrinking every scope into one frame", () => {
    const flow = buildRollupFlowGraph(containers(106));
    const preview = graphConnectionPreview(flow.nodes, flow.edges)!;
    expect(preview.nodes).toHaveLength(6);
    expect(preview.totalNodes).toBe(106);
    expect(preview.edges).toEqual([]);
    expect(preview.nodes.every(node => node.data.rollup?.aggregate.descendant_count === 40)).toBe(true);
  });

  it("retains backend semantic columns regardless of the old grid column option", () => {
    for (const count of [12, 40, 106, 250]) {
      const entries = containers(count);
      const baseline = buildRollupFlowGraph(entries).nodes.map(node => node.position);
      expect(buildRollupFlowGraph(entries, { columns: 3 }).nodes.map(node => node.position)).toEqual(baseline);
      expect(buildRollupFlowGraph(entries).nodes.map(node => node.data.rollup)).toEqual(entries);
    }
  });

  it("bounds the initial window at every estate size and keeps omitted scopes available", () => {
    for (const count of [12, 40, 106, 250, 600]) {
      const flow = buildRollupFlowGraph(containers(count));
      const preview = graphConnectionPreview(flow.nodes, flow.edges)!;
      expect(preview.nodes).toHaveLength(6);
      expect(preview.allNodes).toHaveLength(count);
      expect(new Set(preview.nodes.map(node => node.id)).size).toBe(6);
    }
  });

  it("wraps unlinked sibling scopes of one backend layer into a grid with clear card spacing", () => {
    const { nodes } = buildRollupFlowGraph(containers(3));
    const points = nodes.map(node => node.position);
    for (const [i, a] of points.entries()) for (const b of points.slice(i + 1)) {
      expect(Math.abs(a.x - b.x) >= SEMANTIC_COLUMN_GAP || Math.abs(a.y - b.y) >= SEMANTIC_ROW_GAP).toBe(true);
    }
    expect(new Set(points.map(point => point.x)).size).toBeGreaterThan(1);
  });

  it("lays different semantic layers left-to-right rather than wrapping a grid", () => {
    const layers = ["user", "app", "orchestration", "mcp_server", "tool", "asset"];
    const entries = containers(6).map((entry, i) => ({ ...entry, semantic_layer: layers[i]! }));
    const { nodes } = buildRollupFlowGraph(entries, { columns: 3 });
    const xs = nodes.map(node => node.position.x);
    expect(xs).toEqual([...xs].sort((a, b) => a - b));
    expect(new Set(xs).size).toBe(6);
    expect(new Set(nodes.map(node => node.position.y)).size).toBe(1);
  });

  it("does not fabricate placeholder cards when fewer than six scopes exist", () => {
    const flow = buildRollupFlowGraph(containers(2));
    const preview = graphConnectionPreview(flow.nodes, flow.edges)!;
    expect(preview.nodes.map(node => node.id)).toEqual(flow.nodes.map(node => node.id));
    expect(preview.nodes).toHaveLength(2);
    expect(preview.edges).toEqual([]);
  });
});
