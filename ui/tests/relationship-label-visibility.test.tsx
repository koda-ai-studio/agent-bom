import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { RelationshipEdge } from "@/components/relationship-edge";
import type { EdgeProps } from "@xyflow/react";

vi.mock("@xyflow/react", async (importOriginal) => ({
  ...await importOriginal<typeof import("@xyflow/react")>(),
  useStore: (select: (state: unknown) => unknown) => select({ nodes: [], transform: [0, 0, 1] }),
  useStoreApi: () => ({ getState: () => ({ transform: [0, 0, 1] }), subscribe: () => () => {} }),
  EdgeLabelRenderer: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  BaseEdge: ({ path, markerEnd }: { path: string; markerEnd?: string }) => <path data-testid="relationship-line" d={path} markerEnd={markerEnd} />,
}));

const props = {
  id: "uses", source: "agent", target: "server", sourceX: 0, sourceY: 0,
  targetX: 300, targetY: 0, sourcePosition: "right", targetPosition: "left",
  label: "Uses", markerEnd: "url(#arrow)", data: { relationship: "uses", directionEmphasis: true, hoverDescription: "Recorded usage" },
} as EdgeProps;

describe("relationship label display", () => {
  it("hides the annotation without removing the edge, arrow or evidence tooltip", () => {
    const { container } = render(<svg><RelationshipEdge {...props} data={{ ...props.data, labelVisibility: "hide" }} /></svg>);
    expect(screen.queryByText("Uses")).not.toBeInTheDocument();
    expect(screen.getByTestId("relationship-line")).toHaveAttribute("marker-end", "url(#arrow)");
    expect(container.querySelector("title")).toHaveTextContent("Recorded usage");
    fireEvent.mouseEnter(container.querySelector("g")!);
    expect(screen.queryByText("Uses")).not.toBeInTheDocument();
  });

  it("can explicitly show a label suppressed by overview decluttering", () => {
    render(<RelationshipEdge {...props} label={undefined} data={{ ...props.data, quietLabel: true, labelVisibility: "show" }} />);
    expect(screen.getByText("Uses")).toBeVisible();
  });
});
