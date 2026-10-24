import { fireEvent, render } from "@testing-library/react";
import type { EdgeProps } from "@xyflow/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@xyflow/react", async (importOriginal) => ({
  ...await importOriginal<typeof import("@xyflow/react")>(),
  useStore: (select: (state: unknown) => unknown) => select({
    nodes: [
      { id: "package", position: { x: 0, y: 0 }, data: { nodeType: "package", entityType: "package" } },
      { id: "cve", position: { x: 200, y: 200 }, data: { nodeType: "finding", entityType: "vulnerability" } },
      { id: "config", position: { x: 200, y: 200 }, data: { nodeType: "finding", entityType: "misconfiguration" } },
      { id: "server", position: { x: 0, y: 0 }, data: { nodeType: "server", entityType: "server" } },
    ],
    transform: [0, 0, 1],
  }),
  BaseEdge: ({ markerEnd }: { markerEnd?: string }) => <path data-testid="edge" markerEnd={markerEnd} />,
  EdgeLabelRenderer: ({ children }: { children: React.ReactNode }) => <foreignObject>{children}</foreignObject>,
  useStoreApi: () => ({ getState: () => ({ transform: [0, 0, 1] }), subscribe: () => () => undefined }),
}));
vi.mock("@/lib/relationship-label-layout", () => ({ scheduleRelationshipLabelLayout: vi.fn(), scheduleRelationshipLabelLayoutAfterMove: vi.fn() }));
import { RelationshipEdge } from "@/components/relationship-edge";

const props = {
  id: "package-cve", source: "package", target: "cve", sourceX: 0, sourceY: 0,
  targetX: 200, targetY: 200, sourcePosition: "bottom", targetPosition: "top",
  markerEnd: "url(#target)", label: "Has finding",
  data: { relationship: "vulnerable_to", pathEmphasis: true, directionEmphasis: true },
} as EdgeProps;
function mount(extra: Partial<EdgeProps> = {}) {
  return render(<svg><g className="react-flow__edge" tabIndex={0}><RelationshipEdge {...props} {...extra} /></g></svg>);
}

describe("package to CVE label disclosure", () => {
  it("keeps the arrow but hides the redundant label even on an emphasized path", () => {
    const { queryByText, getByTestId } = mount();
    expect(queryByText("Has finding")).not.toBeInTheDocument();
    expect(getByTestId("edge")).toHaveAttribute("marker-end", "url(#target)");
    expect(getByTestId("edge").parentElement).toHaveAttribute("data-label-disclosure", "on-demand");
  });

  it("reveals on hover and keyboard focus, then hides after inspection", () => {
    const { container, queryByText } = mount();
    const wrapper = container.querySelector(".react-flow__edge")!;
    const edge = wrapper.firstElementChild!;
    fireEvent.mouseEnter(edge);
    expect(queryByText("Has finding")).toBeVisible();
    fireEvent.mouseLeave(edge);
    expect(queryByText("Has finding")).not.toBeInTheDocument();
    fireEvent.focus(wrapper);
    expect(queryByText("Has finding")).toBeVisible();
    fireEvent.blur(wrapper);
    expect(queryByText("Has finding")).not.toBeInTheDocument();
  });

  it("keeps the arrow outside an emphasized path and reveals the selected link", () => {
    const { getByTestId, queryByText, rerender } = mount({ data: { relationship: "vulnerable_to" } });
    expect(getByTestId("edge")).toHaveAttribute("marker-end", "url(#target)");
    expect(getByTestId("edge").parentElement).toHaveAttribute("data-label-disclosure", "on-demand");
    expect(queryByText("Has finding")).not.toBeInTheDocument();
    rerender(<svg><RelationshipEdge {...props} selected /></svg>);
    expect(queryByText("Has finding")).toBeVisible();
  });

  it.each([
    { source: "server", target: "cve" },
    { source: "package", target: "config" },
  ])("keeps finding labels for other endpoint types: $source to $target", (endpoints) => {
    expect(mount(endpoints).getByText("Has finding")).toBeVisible();
  });

  it.each([["assumes", "Assumes"], ["can_access", "Can access"], ["depends_on", "Depends on"]])(
    "keeps the meaningful %s label visible", (relationship, label) => {
      expect(mount({ label, data: { relationship } }).getByText(label)).toBeVisible();
    },
  );
});
