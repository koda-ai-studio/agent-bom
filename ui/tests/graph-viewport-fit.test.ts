import { describe, expect, it } from "vitest";

import { viewportShowsNodes } from "@/lib/graph-viewport-fit";

const nodes = [
  { id: "a", position: { x: 0, y: 0 }, measured: { width: 100, height: 50 } },
  { id: "b", position: { x: 300, y: 400 }, measured: { width: 100, height: 50 } },
];

describe("viewportShowsNodes", () => {
  it("accepts a viewport that keeps every node inside the canvas", () => {
    expect(viewportShowsNodes(nodes, { x: 20, y: 20, zoom: 1 }, { width: 800, height: 600 })).toBe(true);
  });

  it("rejects a restored viewport that pushes the path below the canvas", () => {
    expect(viewportShowsNodes(nodes, { x: 20, y: 500, zoom: 1 }, { width: 800, height: 542 })).toBe(false);
  });

  it("rejects a zoom that pushes a node's centre off the canvas", () => {
    expect(viewportShowsNodes(nodes, { x: 0, y: 0, zoom: 2.5 }, { width: 600, height: 600 })).toBe(false);
  });

  it("tolerates node chrome that overhangs the canvas edge once centred inside it", () => {
    expect(viewportShowsNodes(nodes, { x: -30, y: -10, zoom: 1 }, { width: 400, height: 460 })).toBe(true);
  });

  it("treats unmeasured nodes and an unsized canvas as not yet checkable", () => {
    expect(viewportShowsNodes([{ id: "a", position: { x: 0, y: 0 } }], { x: 0, y: 0, zoom: 1 }, { width: 800, height: 600 })).toBe(true);
    expect(viewportShowsNodes(nodes, { x: 0, y: 900, zoom: 1 }, { width: 0, height: 0 })).toBe(true);
  });
});
