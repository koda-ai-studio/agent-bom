import { describe, expect, it } from "vitest";

import { ATTACK_PATH_FIT_MIN_ZOOM, attackPathFitViewOptions } from "@/lib/graph-viewport";

const options = { padding: 0.12, maxZoom: 1.6, duration: 0 };
const nodes = ["user:a", "role:b", "agent:c", "server:d", "pkg:e", "other:f"].map(id => ({ id, data: {} }));

describe("focused attack path first frame on the investigation canvas", () => {
  it("frames every drawn hop of the path, not a single anchor card", () => {
    const fit = attackPathFitViewOptions(["user:a", "role:b", "agent:c", "server:d", "pkg:e", "cve:not-drawn"], nodes, options, false);
    expect(fit.nodes?.map(node => node.id)).toEqual(["user:a", "role:b", "agent:c", "server:d", "pkg:e"]);
  });

  it("never zooms past natural size to fill the frame, nor below a legible scale", () => {
    for (const narrow of [false, true]) {
      const fit = attackPathFitViewOptions(["user:a", "role:b"], nodes, options, narrow);
      expect(fit.maxZoom).toBeLessThanOrEqual(1);
      expect(fit.minZoom).toBe(ATTACK_PATH_FIT_MIN_ZOOM[narrow ? "narrow" : "desktop"]);
      expect(fit.minZoom).toBeGreaterThanOrEqual(0.5);
    }
  });

  it("falls back to the ordinary options when none of the path is drawn", () => {
    expect(attackPathFitViewOptions(["cve:x"], nodes, options, false)).toEqual(options);
  });
});
