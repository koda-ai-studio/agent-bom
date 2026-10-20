import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";

import { lineageNodeTypes, type LineageNodeData } from "@/components/lineage-nodes";

function renderNode(type: keyof typeof lineageNodeTypes, data: Partial<LineageNodeData> & Pick<LineageNodeData, "label" | "nodeType">) {
  const Renderer = lineageNodeTypes[type];
  return render(<ReactFlowProvider><Renderer data={data as LineageNodeData} /></ReactFlowProvider>).container;
}

const visibleText = (root: HTMLElement) =>
  [...root.querySelectorAll<HTMLElement>("span, p, div")]
    .filter((element) => !element.closest(".sr-only") && element.children.length === 0)
    .map((element) => element.textContent?.trim() ?? "");

describe("finding nodes on the canvas", () => {
  it("keeps CVSS off the canvas and puts it in the hover tooltip", () => {
    const root = renderNode("vulnNode", { label: "CVE-2025-29927", nodeType: "vulnerability", severity: "high", cvssScore: 7.4 });
    expect(visibleText(root).some((text) => /CVSS/.test(text))).toBe(false);
    expect(root.querySelector("[data-graph-entity]")?.getAttribute("title")).toBe("CVE-2025-29927 · High severity · CVSS 7.4");
  });

  it.each(["vulnNode", "misconfigNode"] as const)("shows severity once, as the ring, on %s", (type) => {
    const nodeType = type === "vulnNode" ? "vulnerability" : "misconfiguration";
    const root = renderNode(type, { label: "finding", nodeType, severity: "medium" });
    expect(visibleText(root).filter((text) => /^(critical|high|medium|low)$/i.test(text))).toEqual([]);
    expect(root.querySelector(".graph-entity-glyph")?.className).toContain("border-amber-500");
    expect(root.querySelectorAll("[data-finding-severity]")).toHaveLength(1);
    expect(root.querySelector("[data-finding-severity]")?.textContent).toBe("medium severity");
  });

  it("draws an unrated finding with a neutral dashed ring rather than a guessed severity", () => {
    const root = renderNode("misconfigNode", { label: "finding", nodeType: "misconfiguration" });
    expect(root.querySelector(".graph-entity-glyph")?.className).toContain("border-dashed");
    expect(root.querySelector("[data-graph-entity]")?.getAttribute("title")).toBe("finding · Severity not rated");
  });

  it("keeps KEV as a separate marker", () => {
    const root = renderNode("vulnNode", { label: "CVE-2023-4863", nodeType: "vulnerability", severity: "critical", isKev: true });
    expect(visibleText(root)).toContain("KEV");
  });
});

describe("vendor badge and environment chip on asset nodes", () => {
  const bucket = { label: "customer-pii-bucket", nodeType: "dataStore" as const, entityType: "data_store",
    dimensions: { cloud_provider: "aws", environment: "production" }, attributes: { resource_type: "s3" } };

  it("hides the vendor badge and environment chip that the parent scope already shows", () => {
    const root = renderNode("dataStoreNode", { ...bucket, scopeContext: { provider: "aws", environment: "prod" } });
    expect(root.querySelectorAll("[data-graph-source-badge]")).toHaveLength(0);
    expect(root.querySelectorAll('[data-node-badge="environment"]')).toHaveLength(0);
  });

  it("shows them when the node differs from its scope", () => {
    const root = renderNode("dataStoreNode", { ...bucket, scopeContext: { provider: "snowflake", environment: "staging" } });
    expect(root.querySelectorAll("[data-graph-source-badge]")).toHaveLength(1);
    expect(root.querySelector('[data-node-badge="environment"]')?.textContent).toBe("PROD");
  });

  it("names the asset by its canonical kind and glyph", () => {
    const root = renderNode("dataStoreNode", bucket);
    expect(visibleText(root)).toContain("Bucket");
    expect(root.querySelector(".graph-entity-glyph svg")?.getAttribute("class")).toContain("lucide-archive");
  });

  it("labels a container by its recorded subtype", () => {
    const root = renderNode("containerNode", { label: "ledger-worker", nodeType: "container", entityType: "container", attributes: { container_kind: "workload" } });
    expect(visibleText(root)).toContain("Workload");
    expect(visibleText(root)).not.toContain("Container");
  });
});
