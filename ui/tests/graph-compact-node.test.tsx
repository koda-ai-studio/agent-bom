import { expect, it, vi } from "vitest";
import { fireEvent, render } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import { lineageNodeTypes } from "@/components/lineage-nodes";
import { canvasName, nameBreaks, prosePreview } from "@/components/graph-compact-node";
import { OverviewDetails } from "@/components/lineage-detail/overview";

const aggregate = { issue_count: 3, finding_occurrence_count: 5, worst_severity: "critical", worst_severity_rank: 5,
  descendant_count: 9, by_type: { package: 9 }, severity_counts: { critical: 1, high: 2 },
  internet_exposed: false, exposed_count: 0, toxic_combo: false, toxic_count: 0 };

it.each(["role", "credential", "policy", "accessPolicy"] as const)("does not suggest unknown severity or modeled evidence with a dashed %s outline", kind => {
  const Renderer = lineageNodeTypes.credentialNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "Runtime role", nodeType: kind, semanticLayout: true }} /></ReactFlowProvider>);
  expect(container.querySelector(".graph-entity-glyph")).not.toHaveClass("border-dashed");
});

it("explains a scope count without confusing distinct issues, occurrences, or descendant entities", () => {
  const { getByRole } = render(<OverviewDetails data={{ label: "app", nodeType: "container", findingAggregate: aggregate }} onClose={() => {}} />);
  const summary = getByRole("region", { name: "Finding count scope" });
  expect(summary).toHaveTextContent("Distinct open findings3");
  expect(summary).toHaveTextContent("Finding occurrences5");
  expect(summary).toHaveTextContent("Descendant entities9");
  expect(summary).toHaveTextContent("critical: 1");
  expect(summary).toHaveTextContent("high: 2");
});

it("keeps count inspection usable when older responses omit the histogram and occurrence count", () => {
  const incomplete = { ...aggregate, severity_counts: undefined, finding_occurrence_count: undefined } as unknown as typeof aggregate;
  const { getByRole } = render(<OverviewDetails data={{ label: "app", nodeType: "container", findingAggregate: incomplete }} onClose={() => {}} />);
  expect(getByRole("region", { name: "Finding count scope" })).toHaveTextContent("Finding occurrencesNot available");
});

it("does not present a missing scope issue total as zero", () => {
  const { getByRole } = render(<OverviewDetails data={{ label: "app", nodeType: "container",
    findingAggregate: { ...aggregate, issue_count: undefined } }} onClose={() => {}} />);
  expect(getByRole("region", { name: "Finding count scope" })).toHaveTextContent("Distinct open findingsNot available");
});

it("keeps the authoritative finding count available to collapse expanded findings", () => {
  const Renderer = lineageNodeTypes.containerNode;
  const toggle = vi.fn();
  const { getByRole } = render(<ReactFlowProvider><Renderer data={{ label: "app", nodeType: "container", semanticLayout: true,
    readingFindings: { count: 7, severity: "critical", expanded: true, toggle } }} /></ReactFlowProvider>);
  const button = getByRole("button", { name: "Collapse 7 findings for app" });
  expect(button).toHaveAttribute("aria-expanded", "true");
  fireEvent.click(button);
  expect(toggle).toHaveBeenCalledOnce();
});

it("shows the backend scope count even when its primary finding remains on the path", () => {
  const Renderer = lineageNodeTypes.containerNode;
  const inspect = vi.fn();
  const { getByRole } = render(<ReactFlowProvider><Renderer data={{ label: "app", nodeType: "container", semanticLayout: true,
    findingAggregate: aggregate, onExploreFindings: inspect }} /></ReactFlowProvider>);
  const button = getByRole("button", { name: "Inspect 3 findings in the scope of app" });
  expect(button).not.toHaveAttribute("aria-expanded");
  fireEvent.click(button);
  expect(inspect).toHaveBeenCalledOnce();
});

it("keeps names whole and shortens only image digests", () => {
  expect(canvasName("Reference Evidence Workload")).toBe("Reference Evidence Workload");
  expect(canvasName("reference-evidence-api@sha256:0123456789abcdeff477d58a")).toBe("reference-evidence-api @ f477d58a");
  expect(canvasName("GITHUB_PERSONAL_ACCESS_TOKEN")).toBe("GITHUB_PERSONAL_ACCESS_TOKEN");
  expect(canvasName("an extremely long deployment name with many words")).toBe("an extremely long deployment name with many words");
});

it("draws one circle, a name that may take up to four lines and one type line with no canvas chips", () => {
  const Renderer = lineageNodeTypes.dataStoreNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "Customer data", nodeType: "dataStore", semanticLayout: true,
    attributes: { admin_equivalent: true, data_classification: "confidential", risk_context: { internet_exposed: true } }, isKev: true }} /></ReactFlowProvider>);
  expect(container.querySelector("[data-compact-node]")).not.toBeNull();
  // A long hyphenated name reads whole: the layout leaves room under the card for every line it takes.
  expect(container.querySelector("[data-semantic-name]")).toHaveClass("line-clamp-4");
  expect(container.querySelector("[data-semantic-badges]")).toBeNull();
  expect(container.querySelector('[data-compact-marker="kev"]')).not.toBeNull();
  expect(container.querySelector('[data-compact-marker="internet"]')).not.toBeNull();
});

it("previews a prose finding title in about two lines, cut at a word, and keeps identifiers whole", () => {
  expect(prosePreview("AI agent can reach a credential or privileged tool through a configured MCP server")).toBe("AI agent can reach a credential…");
  expect(prosePreview("CVE-2025-29927")).toBe("CVE-2025-29927");
});

it("wraps a credential identifier only after an underscore, so the whole name stays readable", () => {
  const Renderer = lineageNodeTypes.credentialNode;
  const {container} = render(<ReactFlowProvider><Renderer data={{label: "GITHUB_ENTERPRISE_TOKEN", nodeType: "credential", semanticLayout: true}} /></ReactFlowProvider>);
  expect(container.querySelector("[data-semantic-name]")?.textContent).toBe("GITHUB_ENTERPRISE_TOKEN");
  expect(container.querySelector("[data-semantic-name]")?.getAttribute("title")).toContain("GITHUB_ENTERPRISE_TOKEN");
  expect(nameBreaks("GITHUB_ENTERPRISE_TOKEN").map(piece => piece.text)).toEqual(["GITHUB_", "ENTERPRISE_", "TOKEN"]);
});

it("never splits or truncates a finding id; ordinary names break only after a hyphen or underscore", () => {
  const Renderer = lineageNodeTypes.vulnNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "CVE-2026-108", nodeType: "vulnerability", semanticLayout: true }} /></ReactFlowProvider>);
  const id = container.querySelector("[data-semantic-name] .whitespace-nowrap")!;
  expect(id.textContent).toBe("CVE-2026-108");
  expect(id).not.toHaveClass("truncate");
  expect(container.querySelectorAll("[data-semantic-name] wbr")).toHaveLength(0);
  const Tool = lineageNodeTypes.toolNode;
  const tool = render(<ReactFlowProvider><Tool data={{ label: "Repository token for render_untrusted_image", nodeType: "tool", semanticLayout: true }} /></ReactFlowProvider>);
  const pieces = [...tool.container.querySelectorAll("[data-semantic-name] .truncate")].map(part => part.textContent);
  expect(pieces).toEqual(["Repository", "token", "for", "render_", "untrusted_", "image"]);
  expect(tool.container.querySelectorAll("[data-semantic-name] wbr")).toHaveLength(2);
});


it("lets ordinary names break after a hyphen or underscore, never inside an id, digest or version", () => {
  const pieces = (text: string) => nameBreaks(text).map(piece => `${piece.text}${piece.breakAfter ? "|" : ""}${piece.protect ? "!" : ""}`);
  // The hyphen stays at the end of the line it ends.
  expect(pieces("reference-evidence-api")).toEqual(["reference-|", "evidence-|", "api"]);
  expect(pieces("render_untrusted_image")).toEqual(["render_|", "untrusted_|", "image"]);
  // A version token after "@" never breaks.
  expect(pieces("pillow@9.0.0")).toEqual(["pillow", "@9.0.0!"]);
  expect(pieces("server-github@2025.4.8")).toEqual(["server-|", "github", "@2025.4.8!"]);
  // Finding ids and digests are one unbreakable piece.
  for (const id of ["CVE-2023-4863", "GHSA-abcd-efgh-ijkl", "CWE-79", "f477d58a"]) expect(pieces(id)).toEqual([`${id}!`]);
});

it("puts a finding id under its glyph on a phone, where the card's full width holds it, instead of truncating it beside the glyph", () => {
  const Renderer = lineageNodeTypes.vulnNode;
  const finding = render(<ReactFlowProvider><Renderer data={{ label: "CVE-2025-29927", nodeType: "vulnerability", semanticLayout: true, phoneLayout: true, phoneSide: "right" }} /></ReactFlowProvider>);
  const card = finding.container.querySelector("[data-compact-node]")!;
  expect(card).toHaveClass("flex-col");
  const Role = lineageNodeTypes.serverNode;
  const role = render(<ReactFlowProvider><Role data={{ label: "checkout-runtime", nodeType: "role", semanticLayout: true, phoneLayout: true, phoneSide: "right" }} /></ReactFlowProvider>);
  expect(role.container.querySelector("[data-compact-node]")).toHaveClass("flex-row");
});

it("lets a phone caption beside its glyph take three lines, so a hyphenated server name reads whole", () => {
  const Renderer = lineageNodeTypes.serverNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "github-enterprise MCP", nodeType: "server", semanticLayout: true, phoneLayout: true, phoneSide: "right" }} /></ReactFlowProvider>);
  expect(container.querySelector("[data-semantic-name]")).toHaveClass("line-clamp-3");
});

it("spells each clamp class for the line limit the layout and caption model use", async () => {
  const { NAME_CLAMP } = await import("@/components/graph-compact-node");
  expect(NAME_CLAMP.desktop).toBe(`line-clamp-${NAME_CLAMP.lines.desktop}`);
  expect(NAME_CLAMP.phone).toBe(`line-clamp-${NAME_CLAMP.lines.phone}`);
});

it("names a container's recorded role in its type line when two visible containers share a name", () => {
  const Renderer = lineageNodeTypes.containerNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "reference-evidence-api", nodeType: "container", entityType: "container", semanticLayout: true,
    occurrenceRole: "Image inventory", attributes: {} }} /></ReactFlowProvider>);
  expect(container.querySelector("[data-entity-role]")?.textContent).toBe("Image inventory");
});

it("marks recorded sensitive data without inferring it from an asset name", () => {
  const Renderer = lineageNodeTypes.dataStoreNode;
  const { container, rerender } = render(<ReactFlowProvider><Renderer data={{ label: "Archive", nodeType: "dataStore", semanticLayout: true,
    attributes: { data_sensitivity: "PII", data_classification: "restricted" } }} /></ReactFlowProvider>);
  expect(container.querySelector('[data-compact-marker="sensitive"]')).toHaveAccessibleName("Recorded data classification: PII, restricted");
  for (const attributes of [{}, { data_classification: "public" }, { data_sensitivity: "unknown" }, { data_sensitivity: false }]) {
    rerender(<ReactFlowProvider><Renderer data={{ label: "customer-pii-bucket", nodeType: "dataStore", semanticLayout: true, attributes }} /></ReactFlowProvider>);
    expect(container.querySelector('[data-compact-marker="sensitive"]')).toBeNull();
  }
});


it("uses the reserved caption room for a complete short finding title", () => {
  const Renderer = lineageNodeTypes.vulnNode;
  const label = "Public API stage has no WAF association";
  const { container } = render(<ReactFlowProvider><Renderer data={{ label, nodeType: "misconfiguration", semanticLayout: true, roomyName: true }} /></ReactFlowProvider>);
  expect(container.querySelector("[data-semantic-name]")?.textContent).toBe(label);
});


it("uses one wide phone caption column beside finding glyphs", () => {
  const Renderer = lineageNodeTypes.vulnNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "CVE-2025-29927", nodeType: "vulnerability", semanticLayout: true, phoneLayout: true, phoneLinear: true, phoneSide: "right", roomyName: true }} /></ReactFlowProvider>);
  expect(container.querySelector("[data-compact-node]")).toHaveClass("flex-row");
  expect(container.querySelector("[data-semantic-name]")?.textContent).toBe("CVE-2025-29927");
});


it("shows administrator and critical-asset markers only for recorded verdicts", () => {
  const Renderer = lineageNodeTypes.dataStoreNode;
  const draw = (attributes: Record<string, unknown>) => <ReactFlowProvider><Renderer data={{ label: "admin-critical-pii", nodeType: "dataStore", semanticLayout: true, attributes }} /></ReactFlowProvider>;
  const { container, rerender } = render(draw({ risk_context: { is_admin: true, crown_jewel: true, data_sensitivity: "regulated" } }));
  expect(container.querySelector('[data-compact-marker="privilege"]')).toHaveAccessibleName("Recorded administrator privileges");
  expect(container.querySelector('[data-compact-marker="sensitive"]')).toHaveAccessibleName("Recorded critical asset · data classification: regulated");
  for (const attributes of [{}, { is_admin: "true" }, { privilege_level: "unknown" }, { is_admin: true, risk_context: { is_admin: false, crown_jewel: false } }, { is_admin: true, risk_context: { is_admin: null } }]) {
    rerender(draw(attributes));
    expect(container.querySelector('[data-compact-marker="privilege"]')).toBeNull();
    expect(container.querySelector('[data-compact-marker="sensitive"]')).toBeNull();
  }
});


it("keeps the selected connection focus centred and attaches recorded markers to its glyph", () => {
  const Renderer = lineageNodeTypes.containerNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "Selected asset", nodeType: "container", semanticLayout: true,
    readingFocus: true, attributes: { risk_context: { crown_jewel: true } } }} /></ReactFlowProvider>);
  const focus = container.querySelector<HTMLElement>("[data-reading-focus]")!;
  expect(focus).not.toBeNull();
  expect(focus.style.marginTop).toMatch(/\* -0\./);
  expect(container.querySelector("[data-asset-markers]")).toHaveClass("top-0", "-translate-y-1/2");
});
