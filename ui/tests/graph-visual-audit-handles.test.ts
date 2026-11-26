import { afterEach, expect, it } from "vitest";
import { auditRenderedGraph } from "../scripts/graph-visual-audit.mjs";

afterEach(() => { document.body.innerHTML = ""; });

function audit(vertical: boolean, offset: number, gap = 0) {
  document.body.innerHTML = '<div class="react-flow__node" data-id="a"><div class="graph-entity-glyph"></div></div><div class="react-flow__node" data-id="b"><div class="graph-entity-glyph"></div></div><svg class="react-flow__edge" data-id="edge"><path class="react-flow__edge-path" /></svg>';
  document.querySelectorAll(".graph-entity-glyph").forEach((glyph, i) => {
    glyph.getBoundingClientRect = () => ({ left: vertical ? 0 : i * 100, top: vertical ? i * 100 : 0, width: 40, height: 40 }) as DOMRect;
  });
  Object.assign(document.querySelector("path")!, {
    getScreenCTM: () => ({ a: 1, b: 0, c: 0, d: 1, e: 0, f: 0 }),
    getTotalLength: () => 60,
    getPointAtLength: (length: number) => vertical ? { x: 20 + offset, y: 40 + length + gap } : { x: 40 + length + gap, y: 20 + offset },
  });
  return auditRenderedGraph({ edges: [{ id: "edge", source: "a", target: "b" }] }).misalignedHandles;
}

it.each([false, true])("accepts centered endpoints for vertical=%s", vertical => {
  expect(audit(vertical, 0)).toEqual([]);
});
it.each([false, true])("rejects displaced endpoints for vertical=%s", vertical => {
  expect(audit(vertical, 25)).toEqual([
    { edge: "edge", node: "a", offset: 5 },
    { edge: "edge", node: "b", offset: 5 },
  ]);
});

it.each([false, true])("accepts a fanned endpoint on the glyph rim for vertical=%s", vertical => {
  expect(audit(vertical, 5)).toEqual([]);
});
it.each([false, true])("rejects a detached centerline endpoint for vertical=%s", vertical => {
  expect(audit(vertical, 0, 5)).toEqual([
    { edge: "edge", node: "a", offset: 5 },
    { edge: "edge", node: "b", offset: 5 },
  ]);
});
