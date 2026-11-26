import { afterEach, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
const update = vi.hoisted(() => vi.fn());
vi.mock("@xyflow/react", async (original) => ({
  ...await original<typeof import("@xyflow/react")>(),
  useNodeId: () => "role",
  useUpdateNodeInternals: () => update,
  Handle: () => <span />,
}));
import { CompactGraphNode } from "@/components/graph-compact-node";
afterEach(() => vi.unstubAllGlobals());
it("remeasures handles when a portrait branch changes sides without resizing its glyph", () => {
  vi.stubGlobal("ResizeObserver", class { constructor(private notify: () => void) {} observe() { this.notify(); } disconnect() {} });
  vi.stubGlobal("requestAnimationFrame", (callback: () => void) => { callback(); return 1; });
  vi.stubGlobal("cancelAnimationFrame", () => {});
  const tone = { borderClass: "", bgClass: "", ringClass: "", iconClass: "" };
  const data = { label: "Runtime role", nodeType: "role" as const, phoneLayout: true, phoneSide: "right" as const };
  const { rerender } = render(<CompactGraphNode {...tone} data={data} />);
  update.mockClear();
  rerender(<CompactGraphNode {...tone} data={{ ...data, phoneSide: "left" }} />);
  expect(update).toHaveBeenCalledWith("role");
});
