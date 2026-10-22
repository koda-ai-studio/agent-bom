import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { InvestigationLifecyclePanel, InvestigationLifecycleStrip } from "@/components/investigation-lifecycle";
import type { AttackPath, UnifiedNode } from "@/lib/graph-schema";

const node = (id: string, entity_type: string, label: string, attributes: Record<string, unknown> = {}) =>
  ({ id, entity_type, label, attributes, severity: "critical" }) as unknown as UnifiedNode;
const nodes = [
  node("agent:cursor", "agent", "Cursor"),
  node("server:shell-runner-server", "server", "shell-runner-server"),
  node("pkg:pypi:pyyaml@5.3", "package", "pyyaml@5.3", { name: "pyyaml", version: "5.3", ecosystem: "pypi" }),
  node("vuln:CVE-2020-14343", "vulnerability", "CVE-2020-14343", { fixed_version: "5.4" }),
];
const path = { source: "agent:cursor", target: "vuln:CVE-2020-14343", hops: nodes.map((n) => n.id), edges: [], composite_risk: 95, summary: "", credential_exposure: [], tool_exposure: [], vuln_ids: ["CVE-2020-14343"], severity: "critical" } as AttackPath;
const byId = new Map(nodes.map((n) => [n.id, n]));

describe("fix in context", () => {
  it("preserves the occurrence and historical scan in the Verify continuation", () => {
    render(<InvestigationLifecycleStrip step="fix" completed={{}} onStepChange={() => {}} scanId="scan-7" findingId="finding-7" />);
    expect(screen.getByRole("link", { name: /Verify/ })).toHaveAttribute("href", "/remediation?scan=scan-7&finding=finding-7&view=verification#campaigns");
  });

  it("does not claim a package fix when a non-package finding has no recorded guidance", () => {
    const finding = node("misconfig:unknown", "misconfiguration", "Unconfigured control");
    render(<InvestigationLifecyclePanel step="fix" path={{ ...path, hops: [finding.id], vuln_ids: [] }} nodeById={new Map([[finding.id, finding]])} scanId="current-estate:t" tenantId="t" snapshotGeneration="g" />);
    expect(screen.getByText(/No remediation guidance is recorded/)).toBeVisible();
    expect(screen.getByRole("link", { name: /Open finding workflow/ })).toHaveAttribute("href", "/remediation?view=verification#campaigns");
    expect(screen.queryByText(/No fixed version/)).not.toBeInTheDocument();
  });
  it("shows recorded non-package remediation and carries the finding to its workflow", () => {
    const finding = node("misconfig:reach", "misconfiguration", "Agent credential reach", {
      finding_id: "finding-7", remediation: "Remove the unused credential from the server environment.",
    });
    const nonPackagePath = { ...path, hops: [finding.id], vuln_ids: [], finding_ids: ["finding-7"] };
    render(<InvestigationLifecyclePanel step="fix" path={nonPackagePath} nodeById={new Map([[finding.id, finding]])} scanId="scan-7" tenantId="t" snapshotGeneration="g" />);
    expect(screen.getByText("Remove the unused credential from the server environment.")).toBeVisible();
    expect(screen.queryByText(/No fixed version|Other occurrences of the package/)).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open finding workflow/ })).toHaveAttribute("href", "/remediation?scan=scan-7&finding=finding-7&view=verification#campaigns");
  });
  it("answers Fix on the investigation page with the upgrade, scope and a link out", () => {
    render(<InvestigationLifecyclePanel step="fix" path={path} nodeById={byId} scanId="current-estate:abc" tenantId="t" snapshotGeneration="g" />);
    const panel = screen.getByRole("region", { name: "Fix · CVE-2020-14343" });
    expect(panel).toHaveTextContent("Upgrade pyyaml from 5.3 to 5.4");
    expect(panel).toHaveTextContent("on shell-runner-server, used by Cursor");
    expect(screen.getByRole("link", { name: /Open pyyaml in Remediation/ })).toHaveAttribute("href", "/remediation?q=pyyaml");
  });

  it("says when the advisory records no fixed version instead of inventing one", () => {
    const bare = new Map(byId);
    bare.set("vuln:CVE-2020-14343", node("vuln:CVE-2020-14343", "vulnerability", "CVE-2020-14343"));
    render(<InvestigationLifecyclePanel step="fix" path={path} nodeById={bare} scanId="" tenantId="t" snapshotGeneration="g" />);
    expect(screen.getByText(/No fixed version is recorded for CVE-2020-14343/)).toBeVisible();
  });
});
