import type { Node } from "@xyflow/react";
import { expect, it, vi } from "vitest";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { cloudFindingDisclosure, withFindingDrilldowns } from "@/lib/graph-finding-disclosure";
import { createElement } from "react";
import { render } from "@testing-library/react";
import { GraphAttributeBadges } from "@/components/graph-attribute-badges";

const owner: Node<LineageNodeData> = { id: "owner", position: { x: 400, y: 0 }, data: { label: "Owner", nodeType: "container", rollup: {
  id: "owner", label: "Owner", entity_type: "container", severity: "critical", is_container: true, has_children: true, direct_child_count: 90,
  aggregate: { descendant_count: 100, by_type: {}, severity_counts: { critical: 2 }, worst_severity: "critical", worst_severity_rank: 5,
    internet_exposed: false, toxic_combo: false, exposed_count: 0, toxic_count: 0, issue_count: 41 },
} } };
const finding: Node<LineageNodeData> = { id: "finding", position: { x: 800, y: 0 }, data: {
  label: "Finding", nodeType: "vulnerability", severity: "low", readingOwner: "owner",
} };

it("labels exposed rollup entities without asserting that the owner itself is internet-exposed", () => {
  const data = { ...owner.data, attributes: { internet_exposed: false }, rollup: { ...owner.data.rollup!,
    aggregate: { ...owner.data.rollup!.aggregate, exposed_count: 3, internet_exposed: true } } };
  const { container } = render(createElement(GraphAttributeBadges, { data }));
  expect(container).toHaveTextContent("3 exposed entities");
  expect(container).not.toHaveTextContent("Internet-exposed");
});

it("opens the existing server rollup drilldown instead of expanding the loaded subset", () => {
  const localToggle = vi.fn(), open = vi.fn();
  const result = cloudFindingDisclosure([owner, finding], [], new Set(), localToggle, true);
  const group = withFindingDrilldowns(result.nodes, open).find(n => n.type === "findingGroupNode")!;
  group.data.readingFindings!.toggle();
  expect(open).toHaveBeenCalledExactlyOnceWith(owner.data.rollup);
  expect(localToggle).not.toHaveBeenCalled();
});

it("uses the backend rollup count and severity rather than the loaded finding subset", () => {
  const result = cloudFindingDisclosure([owner, finding], [], new Set(), () => undefined, true);
  const group = result.nodes.find(n => n.type === "findingGroupNode")!;
  expect(group.data.readingFindings?.count).toBe(41);
  expect(group.data.readingFindings?.severity).toBe("critical");
  expect(group.position.x).toBe(owner.position.x);
  expect(group.position.y).toBeGreaterThan(owner.position.y);
  expect(group.data.rollup).toEqual(owner.data.rollup);
});

it("does not replace a missing server aggregate with a local count", () => {
  const result = cloudFindingDisclosure([{ ...owner, data: { ...owner.data, rollup: undefined } }, finding], [], new Set(), () => undefined, true);
  expect(result.nodes.some(n => n.type === "findingGroupNode")).toBe(false);
  expect(result.nodes.find(n => n.id === finding.id)?.hidden).not.toBe(true);
});

it("never collapses an explicit selected-path finding hop", () => {
  const result = cloudFindingDisclosure([owner, { ...finding, data: { ...finding.data, semanticPathIndex: 1 } }], [], new Set(), () => undefined, true);
  expect(result.nodes.find(n => n.id === finding.id)?.hidden).not.toBe(true);
});

import { buildRollupFlowGraph } from "@/lib/graph-rollup-view";
it("lays out roll-up entries by their backend layer and preserves their aggregate", () => {
  const entries = [
    { ...owner.data.rollup!, id: "tool", semantic_layer: "tool" },
    { ...owner.data.rollup!, id: "entry", semantic_layer: "user" },
    { ...owner.data.rollup!, id: "agent", semantic_layer: "orchestration" },
  ];
  const result = buildRollupFlowGraph(entries);
  expect(result.nodes.find(node => node.id === "entry")!.position.x).toBe(0);
  expect(result.nodes.find(node => node.id === "agent")!.position.x).toBeLessThan(result.nodes.find(node => node.id === "tool")!.position.x);
  expect(result.nodes.every(node => node.data.semanticLayout)).toBe(true);
  expect(result.nodes[0]!.data.rollup?.aggregate).toEqual(owner.data.rollup!.aggregate);
});
