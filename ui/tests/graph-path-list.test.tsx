import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Edge, Node } from "@xyflow/react";

import { GraphPathList } from "@/components/graph-path-list";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { graphChains } from "@/lib/graph-chains";
import { COLUMN_MAX_NODES } from "@/lib/path-card-column";

const node = (id: string, nodeType: string, severity?: string): Node<LineageNodeData> => ({
  id, position: { x: 0, y: 0 }, data: { label: id, nodeType, entityType: nodeType, severity } as unknown as LineageNodeData,
});
const edge = (source: string, target: string, relationship = "uses"): Edge => ({ id: `${source}->${target}`, source, target, data: { relationship } });

const nodes = [node("agent", "agent"), node("srv-a", "server"), node("srv-b", "server"), node("pkg-1", "package"), node("cve-1", "vulnerability", "high"), node("pkg-2", "package"), node("orphan", "package")];
const edges = [edge("agent", "srv-a"), edge("agent", "srv-b"), edge("srv-a", "pkg-1", "depends_on"), edge("pkg-1", "cve-1", "vulnerable_to"), edge("srv-b", "pkg-2", "depends_on")];

describe("graphChains", () => {
  it("lists every root-to-leaf chain once, in edge direction", () => {
    const { chains } = graphChains(nodes, edges);
    expect(chains.map(chain => chain.ids)).toEqual([
      ["agent", "srv-a", "pkg-1", "cve-1"],
      ["agent", "srv-b", "pkg-2"],
      ["orphan"],
    ]);
    expect(chains[0]!.relationships).toEqual(["uses", "depends_on", "vulnerable_to"]);
  });

  it("covers every node and bounds long chains to the phone column", () => {
    const long = Array.from({ length: 9 }, (_, index) => node(`n${index}`, "server"));
    const linked = long.slice(1).map((item, index) => edge(long[index]!.id, item.id));
    const { chains, truncated } = graphChains(long, linked);
    expect(chains[0]!.ids).toHaveLength(COLUMN_MAX_NODES);
    expect(chains[0]!.hiddenHops).toBe(3);
    expect(truncated).toBe(false);
  });

  it("survives cycles without looping", () => {
    const { chains } = graphChains([node("a", "server"), node("b", "server")], [edge("a", "b"), edge("b", "a")]);
    expect(chains.flatMap(chain => chain.ids).sort()).toEqual(["a", "b"]);
  });
});

describe("GraphPathList", () => {
  it("renders each chain as a readable column and opens a node", () => {
    const onSelect = vi.fn();
    render(<GraphPathList nodes={nodes} edges={edges} onSelect={onSelect} />);
    const chains = screen.getAllByTestId("graph-path-list-chain");
    expect(chains).toHaveLength(3);
    expect(chains[0]).toHaveTextContent("agent");
    expect(chains[0]).toHaveTextContent("cve-1");
    expect(within(chains[0]!).getByText("Has finding")).toBeInTheDocument();
    fireEvent.click(within(chains[0]!).getByRole("button", { name: /cve-1/ }));
    expect(onSelect).toHaveBeenCalledWith("cve-1");
    expect(screen.getByTestId("graph-path-list")).toHaveTextContent("7 nodes · 3 paths");
  });
});
