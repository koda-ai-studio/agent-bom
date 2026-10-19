import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import { Container, Disc3 } from "lucide-react";

import { LineageDetailPanel } from "@/components/lineage-detail";
import { lineageNodeTypes } from "@/components/lineage-nodes";
import { containerKind, nodeGlyph } from "@/lib/graph-container-kind";
import { ENTITY_ICONS } from "@/lib/entity-icons";

describe("container kind", () => {
  it("reads only the recorded attribute, and only on container nodes", () => {
    expect(containerKind("container", { container_kind: "image" })).toBe("image");
    expect(containerKind("container", { container_kind: "workload" })).toBe("workload");
    expect(containerKind("container", { resource_type: "container_image" })).toBeUndefined();
    expect(containerKind("package", { container_kind: "image" })).toBeUndefined();
  });

  it("gives an image its own glyph, distinct from every entity glyph", () => {
    expect(nodeGlyph("container", { container_kind: "image" })).toBe(Disc3);
    expect(nodeGlyph("container", { container_kind: "workload" })).toBe(Container);
    expect(Object.values(ENTITY_ICONS)).not.toContain(Disc3);
  });

  it.each([
    { kind: "image", badge: "Image" },
    { kind: "workload", badge: "Workload" },
    { kind: undefined, badge: "Container" },
  ])("labels a $kind container as $badge on the canvas and uses one glyph in the inspector", ({ kind, badge }) => {
    const Renderer = lineageNodeTypes.containerNode;
    const data = { label: "member-copilot-00", nodeType: "container" as const, entityType: "container", attributes: kind ? { container_kind: kind } : {} };
    const { container } = render(
      <ReactFlowProvider>
        <section data-testid="node"><Renderer data={data} /></section>
        <LineageDetailPanel data={data} onClose={() => {}} variant="inline" />
      </ReactFlowProvider>,
    );
    const labels = screen.getAllByText(badge, { exact: true });
    expect(labels).toHaveLength(2);
    for (const label of labels) expect(label).toBeVisible();
    const nodeIcon = screen.getByTestId("node").querySelector("svg");
    const inspectorIcon = container.querySelector('[data-testid="graph-entity-drawer"] svg');
    expect(inspectorIcon?.innerHTML).toBe(nodeIcon?.innerHTML);
  });
});
