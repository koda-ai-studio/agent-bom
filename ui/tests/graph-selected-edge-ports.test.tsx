import { render } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { Position } from "@xyflow/react";
import { AttackPathGraphEdge, type AttackPathFlowEdge } from "@/components/attack-path-graph-edge";
import type { EdgeProps } from "@xyflow/react";
vi.mock("@xyflow/react", async importOriginal => ({
  ...await importOriginal<object>(),
  useStore: (select: (state: object) => unknown) => select({ nodes: [], edges: [], transform: [0, 0, 1] }),
  BaseEdge: ({ path }: { path: string }) => <svg><path d={path} /></svg>,
  EdgeLabelRenderer: ({ children }: { children: React.ReactNode }) => children,
}));
it("routes from measured glyph handles rather than stale layout waypoints", () => {
  const props = { id: "edge", source: "a", target: "b", sourceX: 123, sourceY: 64, targetX: 350, targetY: 64,
    sourcePosition: Position.Right, targetPosition: Position.Left,
    data: { edge: { id: "edge", source: "a", target: "b", relationship: "uses", relationshipLabel: "Uses", evidence: "recorded", onPath: false, bidirectional: false },
      direction: "LR", active: false, markerPrefix: "test", route: [{ x: 10, y: 10 }, { x: 30, y: 10 }] },
  } as EdgeProps<AttackPathFlowEdge>;
  const { container } = render(<AttackPathGraphEdge {...props} />);
  expect(container.querySelector("path")!.getAttribute("d")).toMatch(/^M123[, ]64/);
});
