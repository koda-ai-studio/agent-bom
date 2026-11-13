import type { Node } from "@xyflow/react";

/** Clear space kept between any two drawn cards, captions included. */
export const CARD_GAP = 24;
/** Above this many cards the canvas is an overview; React Flow virtualizes and the pass would cost a frame. */
const SEPARATION_NODE_LIMIT = 160;

type Box = { left: number; top: number; right: number; bottom: number };

function box(node: Node): Box | null {
  const width = node.measured?.width, height = node.measured?.height;
  if (node.hidden || !width || !height) return null;
  return { left: node.position.x, top: node.position.y, right: node.position.x + width, bottom: node.position.y + height };
}

const intersects = (a: Box, b: Box, gap: number) =>
  a.left < b.right + gap && a.right + gap > b.left && a.top < b.bottom + gap && a.bottom + gap > b.top;

/** Pairs of drawn cards whose boxes (glyph, name and metadata) intersect. */
export function cardOverlaps(nodes: Node[]): string[] {
  const boxes = nodes.flatMap(node => { const b = box(node); return b ? [{ id: node.id, b }] : []; });
  return boxes.flatMap((a, index) => boxes.slice(index + 1).filter(other => intersects(a.b, other.b, -1)).map(other => `${a.id} x ${other.id}`));
}

/**
 * A layout spaces cards for a nominal size, but a card's caption grows with its name and the zoom
 * it is fitted at. Once React Flow has measured the cards, move any card that would draw over an
 * earlier one: a row neighbour to the right, anything else below. Clear cards never move.
 */
export function separateCards<T extends Node>(nodes: T[]): T[] {
  if (nodes.length > SEPARATION_NODE_LIMIT) return nodes;
  const order = nodes.map((node, index) => ({ node, index, b: box(node) }))
    .filter((item): item is { node: T; index: number; b: Box } => item.b !== null)
    .sort((a, b) => a.b.top - b.b.top || a.b.left - b.b.left);
  const placed: Box[] = [];
  const moved = new Map<number, { x: number; y: number }>();
  for (const item of order) {
    let current = item.b;
    for (let attempt = 0; attempt < nodes.length * 2; attempt++) {
      const blocker = placed.find(other => intersects(current, other, CARD_GAP));
      if (!blocker) break;
      const width = current.right - current.left, height = current.bottom - current.top;
      const sameRow = Math.abs(current.top - blocker.top) < Math.min(height, blocker.bottom - blocker.top) / 2;
      const left = sameRow ? blocker.right + CARD_GAP : current.left;
      const top = sameRow ? current.top : blocker.bottom + CARD_GAP;
      current = { left, top, right: left + width, bottom: top + height };
    }
    placed.push(current);
    if (current.left !== item.b.left || current.top !== item.b.top) moved.set(item.index, { x: current.left, y: current.top });
  }
  if (!moved.size) return nodes;
  return nodes.map((node, index) => moved.has(index) ? { ...node, position: moved.get(index)! } : node);
}
