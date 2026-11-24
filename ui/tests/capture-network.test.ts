import { describe, expect, it } from "vitest";
import { isApiRead, unresolvedAbortedReads } from "../scripts/capture-network.mjs";

describe("aborted API reads in a product-proof capture", () => {
  const base = "http://127.0.0.1:3137";
  it("forgives a superseded read whose endpoint then answered", () => {
    const aborted = [`${base}/v1/graph/node-aggregates?scan_id=a&node_id=x`];
    expect(unresolvedAbortedReads(aborted, new Set(["/v1/graph/node-aggregates"]))).toEqual([]);
  });
  it("fails a read whose endpoint never answered", () => {
    const aborted = [`${base}/v1/graph/node-aggregates?scan_id=a`];
    expect(unresolvedAbortedReads(aborted, new Set(["/v1/graph/snapshots"]))).toEqual(aborted);
  });
  it("only treats API endpoints as reads", () => {
    expect(isApiRead(`${base}/v1/findings`)).toBe(true);
    expect(isApiRead(`${base}/health`)).toBe(true);
    expect(isApiRead(`${base}/_next/static/chunk.js`)).toBe(false);
  });
});
