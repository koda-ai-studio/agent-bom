import { describe, expect, it } from "vitest";
import { Box, Boxes, Container, Layers, Network } from "lucide-react";

import { ENTITY_ICONS, entityIcon, type LineageNodeType } from "@/lib/entity-icons";
import { NODE_TYPE_LEGEND_ORDER, legendItemForNodeType } from "@/lib/graph-utils";

const ALL_TYPES = Object.keys(ENTITY_ICONS) as LineageNodeType[];

describe("graph entity visual identity", () => {
  it("gives every lineage node type its own icon", () => {
    const owners = new Map<unknown, LineageNodeType[]>();
    for (const type of ALL_TYPES) {
      owners.set(ENTITY_ICONS[type], [...(owners.get(ENTITY_ICONS[type]) ?? []), type]);
    }
    const shared = [...owners.values()].filter((types) => types.length > 1);
    expect(shared).toEqual([]);
  });

  it("keeps the unknown-type fallback distinct from every mapped type", () => {
    expect(Object.values(ENTITY_ICONS)).not.toContain(Box);
    expect(entityIcon("not-a-type")).toBe(Box);
  });

  it("does not reuse the generic cube and stack glyphs for infrastructure types", () => {
    const generic = new Set<unknown>([Box, Boxes, Container, Layers, Network]);
    const infrastructure: LineageNodeType[] = ["container", "cloudResource", "environment", "fleet", "cluster"];
    expect(infrastructure.filter((type) => generic.has(ENTITY_ICONS[type]))).toEqual([]);
  });

  it("gives every node type exactly one legend entry that resolves to the node's icon", () => {
    expect([...NODE_TYPE_LEGEND_ORDER].sort()).toEqual([...ALL_TYPES].sort());
    expect(new Set(NODE_TYPE_LEGEND_ORDER).size).toBe(NODE_TYPE_LEGEND_ORDER.length);
    for (const type of ALL_TYPES) {
      const item = legendItemForNodeType(type);
      expect(item.nodeType).toBe(type);
      expect(entityIcon(item.nodeType)).toBe(ENTITY_ICONS[type]);
    }
    const labels = ALL_TYPES.map((type) => legendItemForNodeType(type).label);
    expect(new Set(labels).size).toBe(labels.length);
  });
});
