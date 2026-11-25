import { fireEvent, render } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { Position, type EdgeProps } from "@xyflow/react";
vi.mock("@xyflow/react", async (original) => ({
  ...await original<typeof import("@xyflow/react")>(),
  useStore: (select: (state: unknown) => unknown) => select({ transform: [0, 0, 1], width: 1440, height: 900 }),
  BaseEdge: ({ markerStart, markerEnd }: { markerStart?: string; markerEnd?: string }) => <path data-testid="edge" markerStart={markerStart} markerEnd={markerEnd} />,
  EdgeLabelRenderer: ({ children }: { children: React.ReactNode }) => <foreignObject>{children}</foreignObject>,
}));
import { CompactRelationshipEdge, compactEdgeCurve } from "@/components/graph-compact-edge";
const props = { id: "permission", source: "role", target: "bucket", sourceX: 100, sourceY: 100, targetX: 400, targetY: 100, sourcePosition: Position.Right, targetPosition: Position.Left, markerEnd: "url(#target)", data: { relationship: "has_permission", restingVerb: true } } as EdgeProps;
it("keeps overview links quiet and reveals their exact recorded direction and relationship on inspection", () => {
  const { container, getByTestId, queryByText } = render(<svg><g className="react-flow__edge" tabIndex={0}><CompactRelationshipEdge {...props} /></g></svg>);
  expect(getByTestId("edge")).not.toHaveAttribute("marker-end");
  expect(queryByText("Has Permission")).not.toBeInTheDocument();
  fireEvent.mouseEnter(container.querySelector(".react-flow__edge > g")!);
  expect(getByTestId("edge")).toHaveAttribute("marker-end", "url(#target)");
  expect(queryByText(/Has Permission/)).toBeVisible();
  fireEvent.mouseLeave(container.querySelector(".react-flow__edge > g")!);
  fireEvent.focus(container.querySelector(".react-flow__edge")!);
  expect(getByTestId("edge")).toHaveAttribute("marker-end", "url(#target)");
});
it("keeps an explicitly investigated path named and directed", () => {
  const { getByTestId, queryByText } = render(<svg><CompactRelationshipEdge {...props} data={{ ...props.data, pathLabel: true, directionEmphasis: true }} /></svg>);
  expect(getByTestId("edge")).toHaveAttribute("marker-end", "url(#target)");
  expect(queryByText(/Has Permission/)).toBeVisible();
});

it("keeps a single-column phone context curve within its caption-free side margin", () => {
  const curve = compactEdgeCurve({ sourceX: 100, targetX: 100, sourceY: 0, targetY: 600, sourcePosition: Position.Left, targetPosition: Position.Left, data: { phoneLayout: true, phoneLinear: true } });
  expect(curve.mid.x).toBeGreaterThanOrEqual(76);
  expect(curve.mid.x).toBeLessThan(100);
});
