import { describe, expect, it } from "vitest";
import type { Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { INTERNET_ANCHOR_ID, withInternetAnchor } from "@/lib/graph-internet-context";

const node = (id: string, attributes: Record<string, unknown>): Node<LineageNodeData> =>
  ({ id, position: { x: 0, y: 0 }, data: { label: id, nodeType: "apiGateway", attributes } });
const assessment = { complete: true, decision: "allow", source_scope: "internet", target_id: "ing-1", evidence_refs: ["receipt-1"] };

describe("Internet display anchor", () => {
  it("draws one anchor with a display edge per exposed entry, named for that entry", () => {
    const { nodes, edges } = withInternetAnchor([node("a", { internet_exposed: true }), node("b", { risk_context: { internet_exposed: true } }), node("c", {})], []);
    expect(nodes.filter(n => n.id.startsWith(INTERNET_ANCHOR_ID)).map(n => n.id)).toEqual([INTERNET_ANCHOR_ID]);
    expect(edges.map(e => e.id)).toEqual([`${INTERNET_ANCHOR_ID}:a`, `${INTERNET_ANCHOR_ID}:b`]);
  });

  it("carries a recorded ingress assessment on the exposed entry's display edge, as its receipt", () => {
    const { edges } = withInternetAnchor([node("ingress", { internet_exposed: true, resource_id: "ing-1", network_reachability_assessment: assessment })], []);
    expect(edges[0]!.ariaLabel).toBe("Assessed ingress from Internet to ingress");
    expect(edges[0]!.data?.evidence).toEqual(assessment);
  });

  it("never treats an assessment alone as exposure", () => {
    expect(withInternetAnchor([node("ingress", { resource_id: "ing-1", network_reachability_assessment: assessment })], []).edges).toEqual([]);
  });
});
