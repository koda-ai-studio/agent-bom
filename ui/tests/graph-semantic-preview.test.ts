import type { Node } from "@xyflow/react";
import { expect, it } from "vitest";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { graphConnectionPreview } from "@/lib/graph-connection-preview";

const node = (id: string): Node<LineageNodeData> => ({ id, position: { x: 0, y: 0 }, data: { label: id, nodeType: "server" } });
const edge = (source: string, target: string) => ({ id: `${source}-${target}`, source, target });

it("includes a bounded server-ranked path in the default preview", () => {
  const nodes = Array.from({ length: 8 }, (_, index) => ({ ...node(`n${index}`), data: { ...node(`n${index}`).data, semanticPathIndex: index } }));
  const edges = nodes.slice(1).map((n, index) => edge(nodes[index]!.id, n.id));
  const result = graphConnectionPreview(nodes, edges)!;
  expect(result.nodes.map(n => n.id)).toEqual(nodes.map(n => n.id));
  expect(result.root.id).toBe("n0");
});

it("allocates preview context across sibling branches rather than exhausting the first branch", () => {
  const nodes = ["root", "left", "right", "left-a", "left-b", "right-a", "right-b"].map(node);
  const edges = [edge("root", "left"), edge("root", "right"), edge("left", "left-a"), edge("left", "left-b"), edge("right", "right-a"), edge("right", "right-b")];
  expect(graphConnectionPreview(nodes, edges, "root", 5)!.nodes.map(n => n.id).sort()).toEqual(["root", "left", "right", "left-a", "right-a"].sort());
  expect(graphConnectionPreview(nodes, edges, "root", 12)!.nodes).toHaveLength(7);
});
