import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { AttackPathGraph } from "@/components/attack-path-graph";
import { buildAttackPathGraphModel } from "@/lib/attack-path-graph-model";
import { hopReceiptCoverage } from "@/lib/hop-receipt-coverage";
import { demoFixture, receiptedDemoFixture } from "./fixtures/attack-path-graph-fixture";

beforeAll(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  vi.stubGlobal("DOMMatrixReadOnly", class { m22 = 1; constructor() {} });
});
afterEach(cleanup);

const style = (model: ReturnType<typeof buildAttackPathGraphModel>, source: string, target: string) =>
  model.edges.find(edge => edge.source === source && edge.target === target)!.evidence;

describe("attack path line style follows the hop receipts", () => {
  it("draws a hop with a complete receipt solid even when the edge envelope is modeled", () => {
    const { graph, selected } = receiptedDemoFixture();
    expect(hopReceiptCoverage(selected).evidenced).toBe(6);
    const model = buildAttackPathGraphModel(graph, selected);
    for (const [source, target] of [["user:contractor", "sa:jit"], ["role:admin", "agent:copilot"], ["server:github", "pkg:next"]] as const) {
      expect(style(model, source, target)).toBe("receipt");
    }
    // Branches carry no receipt for this path: their own envelope still decides.
    expect(style(model, "agent:sre", "server:filesystem")).toBe("inferred");
  });

  it("keeps the edge envelope when the hop's receipt falls short", () => {
    const { graph, selected } = receiptedDemoFixture({ 1: { traversable: false }, 3: { relationship_provenance: "inferred" } });
    const model = buildAttackPathGraphModel(graph, selected);
    expect(style(model, "sa:jit", "role:admin")).toBe("inferred");
    expect(style(model, "agent:copilot", "server:github")).toBe("inferred");
    expect(style(model, "user:contractor", "sa:jit")).toBe("receipt");
    expect(hopReceiptCoverage(selected).evidenced).toBe(4);
  });

  it("without receipts the envelope decides, as before", () => {
    const { graph, selected } = demoFixture();
    const model = buildAttackPathGraphModel(graph, selected);
    expect(style(model, "user:contractor", "sa:jit")).toBe("inferred");
  });

  it("draws receipted hops solid and states the rule in the legend", () => {
    const { graph, selected } = receiptedDemoFixture();
    const { container } = render(<AttackPathGraph graph={graph} attackPath={selected} narrow={false} onNodeSelect={vi.fn()} onEdgeSelect={vi.fn()} onOpenFindings={vi.fn()} />);
    const line = container.querySelector('[data-id="user:contractor->sa:jit:acted_as"] path')!;
    expect(line.getAttribute("data-line-style")).toBe("solid");
    const legend = screen.getByRole("list", { name: "Graph legend" });
    expect(within(legend).getByText("Hop receipt: directed, traversable, recorded")).toBeInTheDocument();
  });
});
