import { describe, expect, it } from "vitest";
import { captionGeometry } from "@/lib/graph-caption-geometry";
import { CAPTION_GEOMETRY_SOURCE, graphGrammarExpression } from "../scripts/graph-visual-audit.mjs";
import { captionExtent } from "@/lib/graph-compact-arcs";
import { nameBreaks } from "@/lib/graph-name-breaks";
import { readableGraphNodeStyle } from "@/lib/graph-node-dimensions";

describe("one caption geometry for layout, routing and the gate", () => {
  it("reserves the actual enlarged story type instead of routing through its label", () => {
    const extent = captionExtent({ name: "CVE-2025-32434", typeLine: "critical · Finding", nameScale: 1, readableStory: true }, 300, 1);
    expect(extent.lines[0]!.right - extent.lines[0]!.left).toBeCloseTo(14 * 16 * 0.54 + 8);
    expect(extent.lines[0]!.bottom - extent.lines[0]!.top).toBeCloseTo(16 * 1.15);
    expect(extent.lines[1]!.bottom - extent.lines[1]!.top).toBeCloseTo(13 * 1.15);
    const style = readableGraphNodeStyle(1, true, true, 12, true) as Record<string, string>;
    expect(extent.lines[0]!.bottom - extent.lines[0]!.top).toBeCloseTo(parseFloat(style["--graph-node-label-size"]!) * 1.15);
    expect(extent.lines[1]!.bottom - extent.lines[1]!.top).toBeCloseTo(parseFloat(style["--graph-node-meta-size"]!) * 1.15);
  });
  it("injects the module's own source into the browser gate", () => {
    expect(CAPTION_GEOMETRY_SOURCE).toBe(captionGeometry.toString());
    expect(graphGrammarExpression({ margin: 12 })).toContain(`(${captionGeometry.toString()})`);
  });

  it("is self-contained: its source evaluated in an empty scope behaves the same", () => {
    const injected = new Function(`"use strict"; return (${CAPTION_GEOMETRY_SOURCE});`)() as typeof captionGeometry;
    const input = { name: "Public reference-evidence-api service", typeLine: "Service", box: 216, nameChar: 6.5, metaChar: 6.6, nameLine: 14, metaLine: 14, zoom: 0.6, firstTop: 22, above: 40, pad: 6 };
    const [a, b] = [injected(input), captionGeometry(input)];
    expect({ ...a, hits: undefined }).toEqual({ ...b, hits: undefined });
    for (const [x, y] of [[0, 40], [80, 45], [-120, 60], [0, -10], [0, 200]] as const) for (const part of ["caption", "glyph", "card"] as const)
      expect(a.hits(x, y, part), `${x},${y},${part}`).toBe(b.hits(x, y, part));
  });

  it("breaks names only after a hyphen, underscore or path slash, never inside an id, digest or version", () => {
    const lines = (name: string, chars: number) => captionGeometry({ name, box: chars, nameChar: 1, maxLines: 9 }).nameLines;
    expect(lines("reference-evidence-workload", 20)).toEqual(["reference-evidence-", "workload"]);
    expect(lines("render_untrusted_image", 12)).toEqual(["render_", "untrusted_", "image"]);
    expect(lines("CVE-2023-4863 in pillow", 14)).toEqual(["CVE-2023-4863", "in pillow"]);
    expect(lines("pillow@9.0.0-beta", 7)).toEqual(["pillow@9.0.0-beta"]);
    expect(lines("deploy/values.yaml", 12)).toEqual(["deploy/", "values.yaml"]);
    expect(lines(".github/workflows/", 12)).toEqual([".github/", "workflows/"]);
    expect(lines("prod/web-7c9f-1", 10)).toEqual(["prod/web-", "7c9f-1"]);
    expect(nameBreaks("reference-api").map(piece => piece.text)).toEqual(["reference-", "api"]);
    expect(nameBreaks("GHSA-abcd-efgh-ijkl")).toEqual([{ text: "GHSA-abcd-efgh-ijkl", breakAfter: false, protect: true }]);
  });

  it("reports a clamp when a name needs more lines than it may take", () => {
    const shape = captionGeometry({ name: "Public reference-evidence-api service", box: 12, nameChar: 1 });
    expect(shape.nameLines).toHaveLength(2);
    expect(shape.clamped).toBe(true);
    expect(captionGeometry({ name: "Public reference-evidence-api service", box: 12, nameChar: 1, maxLines: 4 }).clamped).toBe(false);
  });

  it("gives the curve model hyphen-wrapped captions: a hyphenated name takes two lines, not one cut line", () => {
    const extent = captionExtent({ name: "reference-evidence-workload", typeLine: "Service account", box: 216 }, 216, 0.6);
    expect(extent.nameLines).toEqual(["reference-evidence-", "workload"]);
    // The obstacle test covers the second line, and nothing past the widest line or below the type line.
    const second = extent.lines[1]!;
    expect(extent.hits(0, (second.top + second.bottom) / 2, "caption")).toBe(true);
    expect(extent.hits(extent.half + 1, (second.top + second.bottom) / 2, "caption")).toBe(false);
    expect(extent.hits(0, extent.depth + 1, "caption")).toBe(false);
  });
});
