import { render } from "@testing-library/react";
import { beforeAll, expect, it, vi } from "vitest";
import { AttackPathGraph } from "@/components/attack-path-graph";
import { buildAttackPathGraphModel } from "@/lib/attack-path-graph-model";
import { branchingFixture } from "./fixtures/attack-path-graph-fixture";

beforeAll(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  vi.stubGlobal("DOMMatrixReadOnly", class { m22 = 1; });
});

it("draws selected-path edges with the cubic grammar, amber selected steps, neutral context and red privilege", () => {
  const { graph, selected } = branchingFixture();
  const { container } = render(<AttackPathGraph graph={graph} attackPath={selected} narrow={false}
    onNodeSelect={() => undefined} onEdgeSelect={() => undefined} onOpenFindings={() => undefined} />);
  const model = buildAttackPathGraphModel(graph, selected);
  const edges = container.querySelectorAll("path.react-flow__edge-path");
  expect(edges.length).toBeGreaterThan(0);
  for (const edge of edges) {
    expect(edge.getAttribute("d")).toMatch(/C/);
    expect(edge.getAttribute("d")).not.toMatch(/[LQ]/);
    const id = edge.closest("[data-id]")!.getAttribute("data-id");
    const record = graph.edges.find(e => e.id === id);
    if (record) expect(edge).toHaveStyle({ stroke: record.relationship === "can_access" ? "var(--graph-edge-risk)" : model.edges.find(item => item.id === id)?.onPath ? "var(--graph-edge-exposure)" : "var(--graph-edge-structure)" });
  }
});
