import { expect, it } from "vitest";
import { render } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import { lineageNodeTypes } from "@/components/lineage-nodes";
import { canvasName, prosePreview } from "@/components/graph-compact-node";

it("keeps names whole and shortens only image digests", () => {
  expect(canvasName("Reference Evidence Workload")).toBe("Reference Evidence Workload");
  expect(canvasName("reference-evidence-api@sha256:0123456789abcdeff477d58a")).toBe("reference-evidence-api @ f477d58a");
  expect(canvasName("GITHUB_PERSONAL_ACCESS_TOKEN")).toBe("GITHUB_PERSONAL_ACCESS_TOKEN");
  expect(canvasName("an extremely long deployment name with many words")).toBe("an extremely long deployment name with many words");
});

it("draws one circle, a two-line name and one type line with no canvas chips", () => {
  const Renderer = lineageNodeTypes.dataStoreNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "Customer data", nodeType: "dataStore", semanticLayout: true,
    attributes: { admin_equivalent: true, data_classification: "confidential", risk_context: { internet_exposed: true } }, isKev: true }} /></ReactFlowProvider>);
  expect(container.querySelector("[data-compact-node]")).not.toBeNull();
  expect(container.querySelector("[data-semantic-name]")).toHaveClass("line-clamp-2");
  expect(container.querySelector("[data-semantic-badges]")).toBeNull();
  expect(container.querySelector('[data-compact-marker="kev"]')).not.toBeNull();
  expect(container.querySelector('[data-compact-marker="internet"]')).not.toBeNull();
});

it("previews a prose finding title in about two lines, cut at a word, and keeps identifiers whole", () => {
  expect(prosePreview("AI agent can reach a credential or privileged tool through a configured MCP server")).toBe("AI agent can reach a credential…");
  expect(prosePreview("CVE-2025-29927")).toBe("CVE-2025-29927");
});

it("never splits an identifier: a single token stays on one line, words wrap only at spaces", () => {
  const Renderer = lineageNodeTypes.vulnNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "CVE-2026-108", nodeType: "vulnerability", semanticLayout: true }} /></ReactFlowProvider>);
  const words = container.querySelectorAll("[data-semantic-name] span");
  expect(words).toHaveLength(1);
  expect(words[0]).toHaveClass("truncate");
  const Tool = lineageNodeTypes.toolNode;
  const tool = render(<ReactFlowProvider><Tool data={{ label: "Repository token for render_untrusted_image", nodeType: "tool", semanticLayout: true }} /></ReactFlowProvider>);
  const parts = [...tool.container.querySelectorAll("[data-semantic-name] span span")];
  expect(parts.map(part => part.textContent)).toEqual(["Repository", "token", "for", "render_untrusted_image"]);
  expect(parts.every(part => part.classList.contains("whitespace-nowrap"))).toBe(true);
});
