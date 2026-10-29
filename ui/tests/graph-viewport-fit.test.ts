import { describe, expect, it } from "vitest";

import { CONTROLS_OVERLAY, fitPaddingAroundOverlay, fitPaddingPx, viewportShowsNodes } from "@/lib/graph-viewport-fit";

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

  it("rejects a node whose label sits under the bottom-left zoom controls", () => {
    const overlay = CONTROLS_OVERLAY.horizontal;
    // The measured demo path: the CVE node's label reaches 529px on a 542px canvas, under 93x41 controls.
    const lowLeft = [{ id: "cve", position: { x: 55, y: 420 }, measured: { width: 206, height: 109 } }];
    expect(viewportShowsNodes(lowLeft, { x: 0, y: 0, zoom: 1 }, { width: 768, height: 542 })).toBe(true);
    expect(viewportShowsNodes(lowLeft, { x: 0, y: 0, zoom: 1 }, { width: 768, height: 542 }, overlay)).toBe(false);
    expect(viewportShowsNodes(lowLeft, { x: 50, y: 0, zoom: 1 }, { width: 768, height: 542 }, overlay)).toBe(true);
    expect(viewportShowsNodes(lowLeft, { x: 0, y: -40, zoom: 1 }, { width: 768, height: 542 }, overlay)).toBe(true);
    // Vertical controls are 41px wide; a node starting at x=55 clears them.
    expect(viewportShowsNodes(lowLeft, { x: 0, y: 0, zoom: 1 }, { width: 768, height: 542 }, CONTROLS_OVERLAY.vertical)).toBe(true);
    expect(viewportShowsNodes(lowLeft, { x: -30, y: 0, zoom: 1 }, { width: 768, height: 542 }, CONTROLS_OVERLAY.vertical)).toBe(false);
  });

  it("widens the fit padding so the controls corner, plus label growth, stays clear", () => {
    // React Flow reads a numeric padding p on an axis of size s as floor((s - s / (1 + p)) / 2) px.
    expect(fitPaddingPx(0.12, 542)).toBe(29);
    expect(fitPaddingPx(0.2, 768)).toBe(64);
    expect(fitPaddingAroundOverlay(0.12, { width: 768, height: 542 }, CONTROLS_OVERLAY.horizontal))
      .toEqual({ top: 0.12, right: 0.12, bottom: `${41 + 8 + 56}px`, left: `${93 + 8}px` });
    // A generous base padding already clears narrow vertical controls on the left.
    expect(fitPaddingAroundOverlay(0.2, { width: 768, height: 542 }, CONTROLS_OVERLAY.vertical))
      .toEqual({ top: 0.2, right: 0.2, bottom: `${95 + 8 + 56}px`, left: "64px" });
    expect(fitPaddingAroundOverlay(0.12, { width: 0, height: 0 }, CONTROLS_OVERLAY.vertical)).toEqual({ top: 0.12, right: 0.12, bottom: 0.12, left: 0.12 });
  });

  it("treats unmeasured nodes and an unsized canvas as not yet checkable", () => {
    expect(viewportShowsNodes([{ id: "a", position: { x: 0, y: 0 } }], { x: 0, y: 0, zoom: 1 }, { width: 800, height: 600 })).toBe(true);
    expect(viewportShowsNodes(nodes, { x: 0, y: 900, zoom: 1 }, { width: 0, height: 0 })).toBe(true);
  });
});
