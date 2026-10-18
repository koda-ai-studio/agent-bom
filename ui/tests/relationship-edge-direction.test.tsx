import { fireEvent, render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { EdgeProps } from "@xyflow/react";
vi.mock("@xyflow/react", async (importOriginal) => ({
  ...await importOriginal<typeof import("@xyflow/react")>(),
  useStore: (select: (state: unknown) => unknown) => select({ nodes: [], transform: [0, 0, 1] }),
  BaseEdge: ({ markerStart, markerEnd }: { markerStart?: string; markerEnd?: string }) => <path data-testid="edge" markerStart={markerStart} markerEnd={markerEnd} />,
  EdgeLabelRenderer: ({ children }: { children: React.ReactNode }) => <foreignObject>{children}</foreignObject>,
  SmoothStepEdge: () => <path />,
}));
vi.mock("@/lib/relationship-label-layout", () => ({ scheduleRelationshipLabelLayout: vi.fn() }));
import { RelationshipEdge } from "@/components/relationship-edge";

const props = { id: "finding-affects-asset", source: "finding", target: "asset", sourceX: 200, sourceY: 0, targetX: 0, targetY: 0, sourcePosition: "left", targetPosition: "right", markerEnd: "url(#recorded-target)", data: { relationship: "affects", quietLabel: true } } as EdgeProps;
function mount(extra: Partial<EdgeProps> = {}) {
  return render(<svg><g className="react-flow__edge" tabIndex={0}><RelationshipEdge {...props} {...extra} /></g></svg>);
}
describe("progressive relationship direction", () => {
  it("keeps overview connectors quiet, revealing the exact target and verb on hover", () => {
    const { container, getByTestId, getByText } = mount();
    expect(getByTestId("edge")).not.toHaveAttribute("marker-end");
    fireEvent.mouseEnter(container.querySelector(".react-flow__edge > g")!);
    expect(getByTestId("edge")).toHaveAttribute("marker-end", "url(#recorded-target)");
    expect(getByText("Affects")).toBeVisible();
    fireEvent.mouseLeave(container.querySelector(".react-flow__edge > g")!);
    expect(getByTestId("edge")).not.toHaveAttribute("marker-end");
  });
  it("reveals direction for keyboard focus, selection and explicit path investigation", () => {
    const { container, getByTestId, rerender } = mount();
    fireEvent.focus(container.querySelector(".react-flow__edge")!);
    expect(getByTestId("edge")).toHaveAttribute("marker-end", "url(#recorded-target)");
    fireEvent.blur(container.querySelector(".react-flow__edge")!);
    expect(getByTestId("edge")).not.toHaveAttribute("marker-end");
    rerender(<svg><RelationshipEdge {...props} selected /></svg>);
    expect(getByTestId("edge")).toHaveAttribute("marker-end", "url(#recorded-target)");
    rerender(<svg><RelationshipEdge {...props} data={{ ...props.data, directionEmphasis: true }} markerStart="url(#recorded-source)" /></svg>);
    expect(getByTestId("edge")).toHaveAttribute("marker-start", "url(#recorded-source)");
    expect(getByTestId("edge")).toHaveAttribute("marker-end", "url(#recorded-target)");
  });
});

it("keeps neighborhood labels quiet while explicit path steps remain named", () => {
  const { queryByText, rerender } = mount({ label: "Affects", data: { ...props.data, directionEmphasis: true } });
  expect(queryByText("Affects")).not.toBeInTheDocument();
  rerender(<svg><RelationshipEdge {...props} label="Affects" data={{ ...props.data, directionEmphasis: true, pathEmphasis: true }} /></svg>);
  expect(queryByText("Affects")).toBeVisible();
});
