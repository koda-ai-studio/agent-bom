import { render } from "@testing-library/react";
import { expect, it, vi } from "vitest";

import { FindingsQueueTable } from "@/components/findings-queue";
import { GraphChangeExposures } from "@/components/graph-change-exposures";
import type { GraphEstatePathChange } from "@/lib/api-types";
import type { EnrichedVuln } from "@/lib/findings-view";

vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ hasCapability: () => false }) }));

const ESCAPE = /%[0-9A-F]{2}/i;

function tooltips(container: HTMLElement): string[] {
  return [...container.querySelectorAll("[title], [aria-label]")].flatMap((element) =>
    [element.getAttribute("title"), element.getAttribute("aria-label")].filter((value): value is string => Boolean(value)),
  );
}

it("names the reaching node of a finding without percent escapes", () => {
  const row = {
    id: "CVE-fixture", severity: "high", summary: "Fixture", packages: ["example"], current_version: "1.0", agents: [],
    sources: ["SBOM"], detection_source: "SBOM", finding_type: "CVE", advisory_sources: ["OSV"],
    affected_servers: [], exposed_credentials: [], reachable_tools: [], references: [], remediation_items: [],
    graph_reachable: true, graph_min_hop_distance: 2, graph_reachable_from: ["directory:repository:acme/app:project%3Apom"],
  } as unknown as EnrichedVuln;
  const { container } = render(
    <FindingsQueueTable columnProfile="vulnerabilities" vulns={[row]} sortKey="severity" sortDir="desc" handleSort={vi.fn()} pendingExceptions={new Set()} onMarkFP={vi.fn()} selectedId={null} onSelect={vi.fn()} />,
  );
  const titles = tooltips(container);
  expect(titles.some((title) => title.includes("An inbound graph path from directory:repository:acme/app:project:pom"))).toBe(true);
  expect(titles.filter((title) => ESCAPE.test(title))).toEqual([]);
});

it("decodes changed attack path endpoint ids in names and tooltips", () => {
  const path: GraphEstatePathChange = {
    source: "agent:Team%205", target: "vuln:CVE-1", hops: ["agent:Team%205", "vuln:CVE-1"], composite_risk: 80, summary: "",
  };
  const { container } = render(
    <GraphChangeExposures highlights={{ new_attack_paths: { status: "complete", count: 1, top: [path] } }} scanId="new" previousScanId="old" />,
  );
  expect(container).toHaveTextContent("agent:Team 5 → vuln:CVE-1");
  const titles = tooltips(container);
  expect(titles).toContain("agent:Team 5");
  expect(titles.filter((title) => ESCAPE.test(title))).toEqual([]);
});
