import type { Edge, Node } from "@xyflow/react";

/**
 * A connection preview read from its start node: every node sits in the column
 * of its hop distance from the start, so nodes one hop away share one column,
 * two hops the next, and so on. A column stacks at an even row rhythm centred
 * on the start's row, ordered by the rows of its parents so lines into it do
 * not cross. Anything the start does not reach goes in a column after the rest.
 */
export function hopColumnLayout<N extends Node>(nodes: N[], edges: readonly Edge[], rootId: string, { columnGap, rowGap }: { columnGap: number; rowGap: number }): N[] {
  const ids = new Set(nodes.map(node => node.id));
  const neighbours = new Map<string, string[]>();
  for (const edge of edges) {
    if (!ids.has(edge.source) || !ids.has(edge.target) || edge.source === edge.target) continue;
    neighbours.set(edge.source, [...(neighbours.get(edge.source) ?? []), edge.target]);
    neighbours.set(edge.target, [...(neighbours.get(edge.target) ?? []), edge.source]);
  }
  const hop = new Map(ids.has(rootId) ? [[rootId, 0]] : []);
  for (const [id, depth] of hop) for (const next of neighbours.get(id) ?? []) if (!hop.has(next)) hop.set(next, depth + 1);
  const unreached = Math.max(0, ...hop.values()) + 1;
  const columns = new Map<number, N[]>();
  for (const node of nodes) {
    const column = hop.get(node.id) ?? unreached;
    columns.set(column, [...(columns.get(column) ?? []), node]);
  }
  const row = new Map<string, number>();
  const placed = new Map<string, { x: number; y: number }>();
  for (const column of [...columns.keys()].sort((a, b) => a - b)) {
    const parentRow = (node: N) => {
      const rows = (neighbours.get(node.id) ?? []).filter(id => (hop.get(id) ?? unreached) < column && row.has(id)).map(id => row.get(id)!);
      return rows.length ? rows.reduce((sum, value) => sum + value, 0) / rows.length : 0;
    };
    const members = columns.get(column)!.sort((a, b) => parentRow(a) - parentRow(b) || a.position.y - b.position.y || a.id.localeCompare(b.id));
    members.forEach((node, index) => {
      const y = (index - (members.length - 1) / 2) * rowGap;
      row.set(node.id, y);
      placed.set(node.id, { x: column * columnGap, y });
    });
  }
  return nodes.map(node => ({ ...node, position: placed.get(node.id)! }));
}
