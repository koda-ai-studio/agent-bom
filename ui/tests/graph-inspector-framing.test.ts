import { expect, it } from "vitest";
import { graphInspectorTargets } from "@/lib/graph-inspector-framing";

it("frames the finding and its affected asset regardless of layout rank", () => {
  expect(graphInspectorTargets("f", ["f", "asset", "other"], [{ source: "f", target: "asset" }])).toEqual([{ id: "f" }, { id: "asset" }]);
});
it("does not fit missing endpoints or turn a dense selection into an unreadable estate", () => {
  expect(graphInspectorTargets("f", ["f"], [{ source: "f", target: "missing" }])).toEqual([{ id: "f" }]);
  const ids = ["f", ...Array.from({ length: 10 }, (_, i) => String(i))];
  expect(graphInspectorTargets("f", ids, ids.slice(1).map(id => ({ source: id, target: "f" })))).toEqual([{ id: "f" }]);
});
