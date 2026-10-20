import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { PathOwnerPanel } from "@/components/path-owner-panel";
import { packageRemediationHref } from "@/lib/investigation-step-links";

const listFindings = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, listFindings: (...args: unknown[]) => listFindings(...args) } };
});

afterEach(() => listFindings.mockReset());

describe("investigation step links", () => {
  it("sends Fix to the remediation for the path's package, not the findings drawer", () => {
    expect(packageRemediationHref("pillow@9.0.0", "current-estate:abc")).toBe("/remediation?q=pillow");
    expect(packageRemediationHref("@scope/pkg@1.2.3", "scan-1")).toBe("/remediation?q=%40scope%2Fpkg&scan=scan-1");
    expect(packageRemediationHref(undefined, "scan-1")).toBe("/remediation?scan=scan-1");
  });
});

describe("path owner panel", () => {
  it("shows the on-path occurrence's owner and SLA with a route to assign it", async () => {
    listFindings.mockResolvedValue({ findings: [
      { finding_id: "other", node_id: "pkg:x:image", package: "pillow@9.0.0", owner: "wrong-team", sla_due_at: null },
      { finding_id: "f-1", node_id: "pkg:pypi:pillow@9.0.0", package: "pillow@9.0.0", owner: null, sla_due_at: "2099-01-01T00:00:00Z", sla_due_at_source: "severity-kev/v1" },
    ] });
    render(<PathOwnerPanel cve="CVE-2023-4863" hops={["agent:a", "pkg:pypi:pillow@9.0.0"]} packageLabel="pillow@9.0.0" scanId="current-estate:abc" />);
    expect(await screen.findByText("Unassigned")).toBeVisible();
    expect(screen.getByText(/Due in/)).toBeVisible();
    expect(screen.getByText(/Severity and KEV policy/)).toBeVisible();
    expect(screen.getByRole("link", { name: /Assign owner/ })).toHaveAttribute("href", "/findings?finding=f-1");
    expect(listFindings).toHaveBeenCalledWith(expect.objectContaining({ query: "CVE-2023-4863" }));
    expect(listFindings.mock.calls[0]![0]).not.toHaveProperty("scanId");
  });

  it("says plainly when no finding record carries ownership for the path", async () => {
    listFindings.mockResolvedValue({ findings: [] });
    render(<PathOwnerPanel cve="CVE-1" hops={[]} packageLabel="x@1" scanId="scan-1" />);
    expect(await screen.findByText(/No finding record for this path/)).toBeVisible();
  });
});
