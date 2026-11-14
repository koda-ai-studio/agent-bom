import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { fittedViewportHeight } from "../scripts/product-proof-fit.mjs";

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

  it("fits the remediation capture, whose plan is shorter than the viewport", () => {
    const source = fs.readFileSync(path.join(process.cwd(), "scripts", "capture-product-proof.mjs"), "utf8");
    const call = source.slice(source.indexOf('"/remediation?capture=1", "remediation-live.png"'));
    expect(call.slice(0, call.indexOf("});"))).toMatch(/fitContentHeight: \{ selector: "main details/);
    expect(source).toMatch(/if \(options\.fitContentHeight\) await fitViewportToContent\(page, options\.fitContentHeight\);/);
    // The next capture on the same page starts from the viewport it had.
    expect(source).toMatch(/if \(options\.fitContentHeight\) await page\.setViewportSize\(viewport\);/);
  });
});
