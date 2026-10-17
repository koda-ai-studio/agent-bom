import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { GraphCanvasAutoFit } from "@/components/graph-canvas-auto-fit";

const fixture = vi.hoisted(() => ({
  width: 390,
  fitView: vi.fn().mockResolvedValue(true),
  nodes: [
    { id: "agent:a", position: { x: 0, y: 0 }, data: { label: "Same name" } },
    { id: "tool:b", position: { x: 500, y: 0 }, data: { label: "Same name" } },
    { id: "data:c", position: { x: 1000, y: 0 }, data: { label: "Records" } },
  ],
}));
vi.mock("@xyflow/react", async (original) => ({
  ...await original<typeof import("@xyflow/react")>(),
  useNodesInitialized: () => true,
  useStore: (select: (state: unknown) => unknown) => select({ width: fixture.width, height: 600, domNode: null }),
  useReactFlow: () => ({ getNodes: () => fixture.nodes, fitView: fixture.fitView }),
  Panel: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));
const props = { enabled: false, layoutKey: "nodes", inspector: false, preserveViewport: false, onLayoutAspect: vi.fn() };
beforeEach(() => { fixture.width = 390; fixture.fitView.mockClear(); });

it("navigates mobile graph nodes by exact ID when labels repeat", async () => {
  render(<GraphCanvasAutoFit {...props} />);
  expect(screen.getByRole("button", { name: "Previous graph node" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Next graph node" }));
  await waitFor(() => expect(fixture.fitView).toHaveBeenCalledWith(expect.objectContaining({ nodes: [{ id: "tool:b" }] })));
  expect(await screen.findByText(/2 of 3/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Next graph node" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Next graph node" })).toBeDisabled());
});

it("includes the visible target label in its accessible name after navigation", async () => {
  render(<GraphCanvasAutoFit {...props} navigationIds={["agent:a", "data:c"]} />);
  const center = screen.getByRole("button", { name: "Center graph node: Same name" });
  fireEvent.click(center);
  await waitFor(() => expect(fixture.fitView).toHaveBeenCalledWith(expect.objectContaining({ nodes: [{ id: "agent:a" }] })));
  fireEvent.click(screen.getByRole("button", { name: "Next graph node" }));
  expect(await screen.findByRole("button", { name: "Center graph node: Records" })).toHaveTextContent("Records");
});

it("keeps desktop graph controls uncluttered", () => {
  fixture.width = 1200;
  render(<GraphCanvasAutoFit {...props} />);
  expect(screen.queryByRole("button", { name: "Next graph node" })).not.toBeInTheDocument();
});

it("follows ordered path nodes while omitting absent and repeated IDs", async () => {
  render(<GraphCanvasAutoFit {...props} navigationIds={["data:c", "missing", "agent:a", "data:c"]} />);
  expect(screen.getByText(/1 of 2/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Next graph node" }));
  await waitFor(() => expect(fixture.fitView).toHaveBeenCalledWith(expect.objectContaining({ nodes: [{ id: "agent:a" }] })));
  expect(await screen.findByText(/2 of 2/)).toBeInTheDocument();
});

it("does not advance the target when the camera cannot fit it", async () => {
  fixture.fitView.mockResolvedValueOnce(false);
  render(<GraphCanvasAutoFit {...props} />);
  fireEvent.click(screen.getByRole("button", { name: "Next graph node" }));
  await waitFor(() => expect(fixture.fitView).toHaveBeenCalledTimes(1));
  expect(screen.getByText(/1 of 3/)).toBeInTheDocument();
});

it("places navigation outside the canvas so controls cannot cover graph nodes", () => {
  const mount = document.createElement("div");
  document.body.append(mount);
  const result = render(<GraphCanvasAutoFit {...props} navigationMount={mount} />);
  expect(mount.querySelector('[aria-label="Navigate loaded graph nodes"]')).not.toBeNull();
  expect(result.container.querySelector('[aria-label="Navigate loaded graph nodes"]')).toBeNull();
  result.unmount();
  mount.remove();
});
