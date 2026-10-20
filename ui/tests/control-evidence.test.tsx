import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ComplianceControlDrawer } from "@/components/compliance-control-drawer";
import { controlEvidenceExcerpt, controlGraphHref, controlReportSlug } from "@/lib/control-evidence";
import { serverPathFocus } from "@/lib/finding-path-focus";
import type { ComplianceControl } from "@/lib/api";

const getJson = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, getComplianceFrameworkReport: (...args: unknown[]) => getJson(...args) } };
});

const control: ComplianceControl = {
  code: "AC-3", name: "Access Enforcement", findings: 2, status: "fail",
  severity_breakdown: { critical: 1, high: 1 }, affected_packages: ["requests@2.0.0"], affected_agents: ["claude-desktop", "cursor"],
};

afterEach(() => { getJson.mockReset(); });

describe("control evidence links", () => {
  it("opens the graph on the control's own finding set, never its first agent", () => {
    const href = controlGraphHref({ frameworkId: "nist-800-53", control: "AC-3", scanId: "scan-1" });
    const params = new URL(href, "http://x").searchParams;
    expect(params.get("lens")).toBe("attack-path");
    expect(params.get("framework")).toBe("nist-800-53");
    expect(params.get("control")).toBe("AC-3");
    expect(params.get("scan")).toBe("scan-1");
    expect(params.has("agent")).toBe(false);
  });

  it("maps UI framework ids to the signed report slugs", () => {
    expect(controlReportSlug("iso27001")).toBe("iso-27001");
    expect(controlReportSlug("nist-ai-rmf")).toBe("nist");
    expect(controlReportSlug("nist-800-53")).toBe("nist-800-53");
  });

  it("asks the server for the control focus with the investigation", () => {
    expect(serverPathFocus({ framework: "cis", control: "CIS-02.6" })).toEqual({ framework: "cis", control: "CIS-02.6" });
    expect(serverPathFocus({ control: "CIS-02.6" })).toEqual({});
  });

  it("excerpts one control and keeps the bundle's signature reference", () => {
    const bundle = {
      framework: "nist-800-53", generated_at: "2026-10-19T00:00:00Z", nonce: "n1", signature: "sig", signature_algorithm: "HMAC-SHA256",
      controls: [{ control_id: "AC-3", evidence: [{ id: 1 }] }, { control_id: "AC-6", evidence: [] }],
    };
    const excerpt = controlEvidenceExcerpt(bundle, "AC-3");
    expect(excerpt.control).toEqual({ control_id: "AC-3", evidence: [{ id: 1 }] });
    expect(excerpt.excerpt_of).toMatchObject({ framework: "nist-800-53", nonce: "n1", signature: "sig" });
    expect(() => controlEvidenceExcerpt(bundle, "ZZ-1")).toThrow(/not in the signed bundle/);
  });
});

describe("control drawer", () => {
  it("labels occurrences and issues as separate units", () => {
    render(<ComplianceControlDrawer control={{ ...control, findings: 556, issue_count: 41 }} frameworkId="nist-800-53" frameworkLabel="NIST" onClose={() => {}} />);
    expect(screen.getByText("556 finding occurrences · 41 issues mapped to this control.")).toBeInTheDocument();
  });

  it("uses singular units for one occurrence and one issue", () => {
    render(<ComplianceControlDrawer control={{ ...control, findings: 1, issue_count: 1 }} frameworkId="nist-800-53" frameworkLabel="NIST" onClose={() => {}} />);
    expect(screen.getByText("1 finding occurrence · 1 issue mapped to this control.")).toBeInTheDocument();
  });

  it("falls back to the occurrence unit alone for older API payloads", () => {
    render(<ComplianceControlDrawer control={{ ...control, findings: 3 }} frameworkId="nist-800-53" frameworkLabel="NIST" onClose={() => {}} />);
    expect(screen.getByText("3 finding occurrences mapped to this control.")).toBeInTheDocument();
  });

  it("links affected assets to their own pages", () => {
    render(<ComplianceControlDrawer control={control} frameworkId="nist-800-53" frameworkLabel="NIST" onClose={() => {}} />);
    fireEvent.click(screen.getByRole("tab", { name: "Overview" }));
    const agent = screen.getByRole("link", { name: "Claude Desktop" });
    expect(agent).toHaveAttribute("href", "/agents?name=claude-desktop");
    expect(agent).toHaveAttribute("title", "claude-desktop");
    expect(screen.getByRole("link", { name: "Cursor" })).toHaveAttribute("href", "/agents?name=cursor");
    expect(screen.getByRole("link", { name: "requests@2.0.0" })).toHaveAttribute("href", "/findings?q=requests%402.0.0");
  });

  it("exports the control's evidence from the signed framework bundle", async () => {
    getJson.mockResolvedValue({ framework: "nist-800-53", nonce: "n1", signature: "sig", controls: [{ control_id: "AC-3", evidence: [] }] });
    const createObjectURL = vi.fn(() => "blob:x");
    Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() });
    render(<ComplianceControlDrawer control={control} frameworkId="nist-800-53" frameworkLabel="NIST" onClose={() => {}} />);
    fireEvent.click(screen.getByRole("tab", { name: "Actions" }));
    expect(screen.getByRole("link", { name: "Evidence in security graph" })).toHaveAttribute(
      "href", "/security-graph?lens=attack-path&framework=nist-800-53&control=AC-3",
    );
    fireEvent.click(screen.getByRole("button", { name: "Export control evidence" }));
    await waitFor(() => expect(createObjectURL).toHaveBeenCalled());
    expect(getJson).toHaveBeenCalledWith("nist-800-53");
  });
});
