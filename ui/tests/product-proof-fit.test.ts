import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { fittedViewportHeight, nextCaptureWidth, OFFSCREEN_NODES_TEXT } from "../scripts/product-proof-fit.mjs";
import { architecturePages } from "./fixtures/agent-architecture-fixture";

describe("fitting a short page's capture to its content", () => {
  it("ends the capture just below the content", () => {
    expect(fittedViewportHeight(566, 900)).toBe(598);
    expect(fittedViewportHeight(566, 900, { pad: 24 })).toBe(590);
  });

  it("never grows the viewport, never shrinks below the floor, and ignores a missing measurement", () => {
    expect(fittedViewportHeight(1400, 900)).toBe(900);
    expect(fittedViewportHeight(120, 900, { min: 480 })).toBe(480);
    expect(fittedViewportHeight(0, 900)).toBe(900);
    expect(fittedViewportHeight(Number.NaN, 900)).toBe(900);
  });

  it("fits both desktop remediation captures, whose plan is shorter than the viewport", () => {
    const source = fs.readFileSync(path.join(process.cwd(), "scripts", "capture-product-proof.mjs"), "utf8");
    expect(source).toMatch(/const REMEDIATION_FIT = \{ selector: "main details"/);
    for (const file of ["remediation-live.png", "remediation-light-live.png"]) {
      const call = source.slice(source.indexOf(`"/remediation?capture=1", "${file}"`));
      expect(call.slice(0, call.indexOf("});"))).toMatch(/fitContentHeight: REMEDIATION_FIT/);
    }
    expect(source).toMatch(/if \(options\.fitContentHeight\) await fitViewportToContent\(page, options\.fitContentHeight\);/);
    // The next capture on the same page starts from the viewport it had.
    expect(source).toMatch(/if \(options\.fitContentHeight\) await page\.setViewportSize\(viewport\);/);
  });

  it("grows a capture to content longer than the viewport only up to an explicit ceiling", () => {
    expect(fittedViewportHeight(1420, 980, { max: 1800 })).toBe(1452);
    expect(fittedViewportHeight(2400, 980, { max: 1800 })).toBe(1800);
    expect(fittedViewportHeight(1420, 980)).toBe(980);
    expect(fittedViewportHeight(566, 980, { max: 1800 })).toBe(598);
  });

  it("widens a clipped graph step by step and stops at the ceiling", () => {
    expect(nextCaptureWidth(1440, { step: 160, max: 2400 })).toBe(1600);
    expect(nextCaptureWidth(2320, { step: 160, max: 2400 })).toBe(2400);
    expect(nextCaptureWidth(2400, { step: 160, max: 2400 })).toBeNull();
    expect(OFFSCREEN_NODES_TEXT.test("2 more nodes off screen · drag to pan")).toBe(true);
    expect(OFFSCREEN_NODES_TEXT.test("1 more node off screen · drag to pan")).toBe(true);
  });
});

describe("agent architecture capture", () => {
  const source = fs.readFileSync(path.join(process.cwd(), "scripts", "product-proof-agent-architecture.mjs"), "utf8");

  it("lets the layered capture grow past the 980px viewport instead of cutting the tree", () => {
    expect(source).toMatch(/HARNESS_FIT = \{[^}]*max: 1800 \}/);
    const layered = source.slice(source.indexOf('"agent-architecture-layered-dark-live.png", async'));
    expect(layered.slice(0, layered.indexOf("darkPage.close()"))).not.toContain("widenUntilNoNodesOffscreen");
    expect(source.match(/fitContentHeight: HARNESS_FIT/g)).toHaveLength(2);
  });

  it("widens the flow capture until no node is off screen and rejects a clipped frame", () => {
    const flow = source.slice(source.indexOf('"agent-architecture-flow-light-live.png", async'));
    expect(flow.slice(0, flow.indexOf("lightPage.close()"))).toContain("await widenUntilNoNodesOffscreen(target, FLOW_WIDTH);");
    expect(source).toMatch(/rejectedText: \[[^\]]*OFFSCREEN_NODES_TEXT\]/);
  });

  it("gives every harness in the fixture a distinct label", () => {
    const pages = architecturePages();
    const labels = [...pages.first_page.harnesses, ...pages.second_page.harnesses].map(harness => harness.label);
    expect(new Set(labels).size).toBe(labels.length);
  });
});
