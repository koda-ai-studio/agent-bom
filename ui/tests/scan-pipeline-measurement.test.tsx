import { act, fireEvent, render } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Node, NodeChange } from "@xyflow/react";
import type { StepEvent } from "@/lib/api";

const flow = vi.hoisted(() => ({
  nodes: [] as Node[],
  onNodesChange: undefined as ((changes: NodeChange[]) => void) | undefined,
  api: { fitView: vi.fn(), getNode: vi.fn(), setViewport: vi.fn(), viewportInitialized: false },
}));
vi.mock("@xyflow/react", async importOriginal => ({
  ...await importOriginal<typeof import("@xyflow/react")>(),
  ReactFlowProvider: ({ children }: { children: React.ReactNode }) => children,
  ReactFlow: (props: { nodes: Node[]; onNodesChange?: (changes: NodeChange[]) => void }) => {
    flow.nodes = props.nodes;
    flow.onNodesChange = props.onNodesChange;
    return <div />;
  },
  useReactFlow: () => flow.api,
}));
import { ScanPipeline } from "@/components/scan-pipeline";

const steps = (message: string) => new Map<string, StepEvent>([
  ["discovery", { type: "step", step_id: "discovery", status: "done", message }],
]);

describe("controlled pipeline node measurements", () => {
  beforeEach(() => { flow.nodes = []; flow.onNodesChange = undefined; });
  it("retains measured geometry when stage telemetry refreshes", () => {
    const { rerender } = render(<ScanPipeline steps={steps("First event")} />);
    act(() => flow.onNodesChange?.([{ id: "discovery", type: "dimensions", dimensions: { width: 240, height: 126 } }]));
    rerender(<ScanPipeline steps={steps("Updated event")} />);
    const discovery = flow.nodes.find(node => node.id === "discovery")!;
    expect(discovery.data.message).toBe("Updated event");
    expect(discovery.measured).toEqual({ width: 240, height: 126 });
    act(() => flow.onNodesChange?.([{ id: "discovery", type: "dimensions", dimensions: { width: 240, height: 150 } }]));
    expect(flow.nodes.find(node => node.id === "discovery")!.measured).toEqual({ width: 240, height: 150 });
  });
  it("keeps compact and readable measurements separate", () => {
    const { getByRole } = render(<ScanPipeline steps={steps("Ready")} />);
    act(() => flow.onNodesChange?.([{ id: "discovery", type: "dimensions", dimensions: { width: 240, height: 126 } }]));
    fireEvent.click(getByRole("button", { name: "Fit overview" }));
    expect(flow.nodes.find(node => node.id === "discovery")!.measured).toBeUndefined();
    act(() => flow.onNodesChange?.([{ id: "discovery", type: "dimensions", dimensions: { width: 160, height: 56 } }]));
    expect(flow.nodes.find(node => node.id === "discovery")!.measured).toEqual({ width: 160, height: 56 });
    fireEvent.click(getByRole("button", { name: "Readable view" }));
    expect(flow.nodes.find(node => node.id === "discovery")!.measured).toEqual({ width: 240, height: 126 });
  });
});
