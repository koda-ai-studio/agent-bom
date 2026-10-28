import { render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";

import { FindingsQueueTable } from "@/components/findings-queue";
import type { EnrichedVuln } from "@/lib/findings-view";

vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ hasCapability: () => false }) }));

const LONG_VERIFY = "pip show requests | grep -E '^Version: 2\\.32\\.4$' && pip-audit --strict";

function row(overrides: Partial<EnrichedVuln> = {}): EnrichedVuln {
  return {
    id: "CVE-remediation", severity: "high", summary: "Fixture finding", packages: ["requests"], current_version: "2.0", agents: [],
    sources: ["SBOM", "CVE"], detection_source: "SBOM", finding_type: "CVE", advisory_sources: ["OSV"],
    affected_servers: [], exposed_credentials: [], reachable_tools: [], references: [], remediation_items: [],
    fixed_version: "2.32.4", last_observed: "2026-09-01T00:00:00Z",
    ...overrides,
  };
}

function mount(vuln: EnrichedVuln) {
  return render(
    <FindingsQueueTable columnProfile="all" vulns={[vuln]} sortKey="severity" sortDir="desc" handleSort={vi.fn()}
      pendingExceptions={new Set()} onMarkFP={vi.fn()} selectedId={null} onSelect={vi.fn()} />,
  );
}

it("spells out the missing verify command in full instead of clipping it", () => {
  mount(row());
  const empty = screen.getByText("No verify command");
  expect(empty.textContent).toBe("No verify command");
  expect(empty.className).not.toMatch(/truncate|max-w-/);
  expect(screen.queryByText(/No scanner-provided/)).not.toBeInTheDocument();
});

it("keeps a real verify command on one truncated line with the full command in the tooltip", () => {
  const item = { package: "requests", verify_command: LONG_VERIFY } as unknown as EnrichedVuln["remediation_items"][number];
  mount(row({ remediation_items: [item] }));
  const verify = screen.getByText(`Verify: ${LONG_VERIFY}`);
  expect(verify.className).toMatch(/truncate/);
  expect(verify).toHaveAttribute("title", expect.stringContaining(LONG_VERIFY));
  expect(screen.queryByText("No verify command")).not.toBeInTheDocument();
});

it("shows no verify line at all when neither a fix nor a command exists", () => {
  mount(row({ fixed_version: undefined }));
  expect(screen.getByText("Fix not provided")).toBeInTheDocument();
  expect(screen.queryByText("No verify command")).not.toBeInTheDocument();
});
