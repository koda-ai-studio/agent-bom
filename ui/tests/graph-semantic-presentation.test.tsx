import { expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import { lineageNodeTypes } from "@/components/lineage-nodes";
import { graphSemanticRiskLabel } from "@/components/graph-attribute-badges";
import { flowEdgeLegend } from "@/lib/graph-flow-legend";
import { nodeContextMarkers } from "@/lib/attack-path-graph-markers";
import { GraphPathList } from "@/components/graph-path-list";
import { GraphConnectionPreviewControls } from "@/components/graph-connection-preview-controls";
import { graphConnectionPreview } from "@/lib/graph-connection-preview";

it("offers explicit connection expansion from the bounded preview", () => {
  const preview = graphConnectionPreview([{ id: "one", position: { x: 0, y: 0 }, data: { label: "One", nodeType: "server" } }], [])!;
  let expanded = false;
  render(<GraphConnectionPreviewControls preview={preview} expanded={false} onRoot={() => undefined} onExplore={() => undefined} onExpanded={value => { expanded = value; }} />);
  fireEvent.click(screen.getByRole("button", { name: /Show more connections/ }));
  expect(expanded).toBe(true);
});

it("labels mobile root-to-leaf chains as connections, never as assessed attack paths", () => {
  render(<GraphPathList nodes={[{ id: "one", position: { x: 0, y: 0 }, data: { label: "One", nodeType: "server" } }]}
    edges={[]} onSelect={() => undefined} />);
  expect(screen.getByTestId("graph-path-list")).toHaveTextContent("1 node · 1 connection chain");
  expect(screen.getByTestId("graph-path-list")).not.toHaveTextContent(/1 paths?/);
});

it("reads the canonical admin flag and folded exposure independently of legacy reasons", () => {
  const markers = nodeContextMarkers({ admin_equivalent: true, internet_exposed: true, risk_context: { internet_exposed: false } });
  expect(markers.some(marker => marker.kind === "privileged")).toBe(true);
  expect(markers.some(marker => marker.kind === "internet")).toBe(false);
  expect(nodeContextMarkers({ risk_context: { internet_exposed: true } }).some(marker => marker.kind === "internet")).toBe(true);
});

it("keeps the full name in a tooltip and the visible name to one line above its type", () => {
  const label = "an extremely long deployment name with enough words to wrap repeatedly";
  const Renderer = lineageNodeTypes.containerNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label, nodeType: "container", semanticLayout: true, evidenceFlow: true }} /></ReactFlowProvider>);
  const caption = container.querySelector("[data-semantic-name]");
  expect(caption).toHaveAttribute("title", label);
  expect(caption).toHaveClass("truncate");
  expect(container.querySelector("[data-entity-role]")).toHaveClass("truncate");
});

it("shows recorded privilege, sensitive data and KEV above the node", () => {
  const Renderer = lineageNodeTypes.dataStoreNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "Customer data", nodeType: "dataStore", semanticLayout: true,
    attributes: { admin_equivalent: true, data_classification: "confidential" }, isKev: true }} /></ReactFlowProvider>);
  const badges = container.querySelector("[data-semantic-badges]");
  expect(badges).toHaveTextContent(/Privileged/);
  expect(badges).toHaveTextContent(/Sensitive/);
  expect(badges).toHaveTextContent("KEV");
  expect(screen.getByText("Customer data")).toBeInTheDocument();
});

it("shows a supplied risk score without claiming an undocumented assessment", () => {
  expect(graphSemanticRiskLabel(72, undefined)).toContain("72.0");
  expect(graphSemanticRiskLabel(72, undefined)).toMatch(/not recorded/i);
  expect(graphSemanticRiskLabel(undefined, undefined)).toBe("Not assessed");
});

it("shows the supplied risk score on the semantic node with its assessment qualification", () => {
  const Renderer = lineageNodeTypes.containerNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "Workload", nodeType: "container", semanticLayout: true, riskScore: 72 }} /></ReactFlowProvider>);
  expect(container.querySelector("[data-semantic-risk]")).toHaveTextContent("72.0");
  expect(container.querySelector("[data-semantic-risk]")).toHaveTextContent(/not recorded/i);
});

it("lists only drawn relationship kinds even when only one kind is present", () => {
  const result = flowEdgeLegend([{ id: "a", source: "a", target: "b", data: { relationship: "uses" }, style: { stroke: "green" } },
    { id: "hidden", source: "b", target: "c", hidden: true, data: { relationship: "contains" }, style: { stroke: "blue" } }]);
  expect(result.relationships.map(entry => entry.relationship)).toEqual(["uses"]);
});

it("does not promote legacy hints into canonical attribute badges", () => {
  expect(nodeContextMarkers({ is_admin: true, escalates_to_admin: true, sensitivity: "secret" })).toEqual([]);
  const markers = nodeContextMarkers({ admin_equivalent: true, privilege_level: "admin", data_classification: "confidential",
    risk_context: { internet_exposed: false } });
  expect(markers.map(marker => marker.kind).sort()).toEqual(["privileged", "sensitive"]);
});

it("keeps badges outside the glyph baseline and omits an unassessed default zero", () => {
  const Renderer = lineageNodeTypes.containerNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "Workload", nodeType: "container", semanticLayout: true,
    riskScore: 0, attributes: { admin_equivalent: true } }} /></ReactFlowProvider>);
  expect(container.querySelector("[data-semantic-badges]")).not.toHaveClass("absolute");
  expect(container.querySelector("[data-semantic-risk]")).toBeNull();
});

it("keeps zoom-compensated badge rows below the glyph and its two-line label", () => {
  const Renderer = lineageNodeTypes.containerNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "Workload", nodeType: "container", semanticLayout: true,
    riskScore: 8, attributes: { admin_equivalent: true, data_classification: "restricted" } }} /></ReactFlowProvider>);
  const glyph = container.querySelector('.graph-entity-glyph')!;
  const name = container.querySelector('[data-semantic-name]')!;
  const badges = container.querySelector('[data-semantic-badges]')!;
  expect(Boolean(glyph.compareDocumentPosition(badges) & Node.DOCUMENT_POSITION_FOLLOWING)).toBe(true);
  expect(Boolean(name.compareDocumentPosition(badges) & Node.DOCUMENT_POSITION_FOLLOWING)).toBe(true);
});

it.each(["package", "finding", "runtime_evidence"])("renders owned %s context as a compact sub-row without changing its backend badges", semanticLayer => {
  const Renderer = lineageNodeTypes.packageNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "Recorded context", nodeType: "package", semanticLayout: true,
    semanticLayer, semanticOwner: "workload", attributes: { data_classification: "restricted" } }} /></ReactFlowProvider>);
  expect(container.querySelector('[data-graph-subrow="workload"]')).not.toBeNull();
  expect(container.querySelector('.graph-entity-glyph')).toHaveStyle({ width: "40px", height: "40px" });
  expect(container.querySelector('[data-semantic-name]')).toHaveClass("col-start-2");
  expect(container.querySelector('[data-semantic-badges]')).toHaveTextContent("Sensitive data");
});

it("retains a full glyph for a package explicitly retained on the selected spine", () => {
  const Renderer = lineageNodeTypes.packageNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "Selected package", nodeType: "package", semanticLayout: true,
    semanticLayer: "package", semanticPathIndex: 2 }} /></ReactFlowProvider>);
  expect(container.querySelector('[data-graph-subrow]')).toBeNull();
  expect(container.querySelector('.graph-entity-glyph')).not.toHaveStyle({ width: "40px" });
});
