import { describe, expect, it } from "vitest";
import type { Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { CARD_GAP, cardOverlaps, separateCards } from "@/lib/graph-card-separation";
import { wrappedRankLayout } from "@/lib/graph-wrapped-ranks";
import { flowRowGap, FLOW_COLUMN_GAP } from "@/lib/graph-flow-layout";
import { PREVIEW_LAYOUT, PREVIEW_CARD_MAX_WIDTH } from "@/lib/graph-preview-layout";

type FlowNode = Node<LineageNodeData>;
const card = (id: string, x: number, y: number, width = 220, height = 240): FlowNode =>
  ({ id, position: { x, y }, measured: { width, height }, data: { label: id, nodeType: "server" } });

describe("separateCards", () => {
  it("moves a tall card's lower neighbour below its caption instead of drawing over it", () => {
    const nodes = separateCards([card("finding", 0, 0, 220, 330), card("cve", 0, 300)]);
    expect(cardOverlaps(nodes)).toEqual([]);
    expect(nodes.find(node => node.id === "cve")!.position.y).toBe(330 + CARD_GAP);
  });

  it("moves a same-row neighbour right when wide captions meet, keeping the row", () => {
    const nodes = separateCards([card("flask", 0, 0, 340), card("key", 320, 0, 340)]);
    expect(cardOverlaps(nodes)).toEqual([]);
    expect(nodes.find(node => node.id === "key")!.position.y).toBe(0);
  });

  it("settles a chain of overlaps and leaves clear cards and unmeasured cards where they are", () => {
    const input = [card("a", 0, 0, 220, 400), card("b", 0, 260), card("c", 0, 520), card("far", 900, 0), { id: "new", position: { x: 0, y: 100 }, data: { label: "new", nodeType: "server" } } as FlowNode];
    const nodes = separateCards(input);
    expect(cardOverlaps(nodes.filter(node => node.measured))).toEqual([]);
    expect(nodes.find(node => node.id === "far")!.position).toEqual({ x: 900, y: 0 });
    expect(nodes.find(node => node.id === "new")!.position).toEqual({ x: 0, y: 100 });
    expect(separateCards(nodes)).toEqual(nodes);
  });
});

describe("layout fixtures leave room for a card and its caption", () => {
  // The widest caption a card may draw and the tallest it reaches at the fitted-overview floor.
  const WIDTH = PREVIEW_CARD_MAX_WIDTH, HEIGHT = 300;
  const sized = (nodes: FlowNode[]) => nodes.map(node => ({ ...node, measured: { width: WIDTH, height: HEIGHT } }));

  it("spaces preview columns and rows wider than any card", () => {
    const ranks = Array.from({ length: 9 }, (_, index) => card(`n${index}`, (index % 4) * 240, Math.floor(index / 4) * 200));
    const laid = sized(wrappedRankLayout(ranks, PREVIEW_LAYOUT));
    expect(cardOverlaps(laid)).toEqual([]);
  });

  it("keeps flow grid cells wider and taller than any card", () => {
    expect(FLOW_COLUMN_GAP).toBeGreaterThan(WIDTH + CARD_GAP / 2);
    expect(flowRowGap(false)).toBeGreaterThan(HEIGHT + CARD_GAP / 2);
    expect(flowRowGap(true)).toBeGreaterThan(HEIGHT + CARD_GAP / 2);
  });
});
