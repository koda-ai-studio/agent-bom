import { readFileSync } from "node:fs";
import { expect, test, type Locator, type Page, type TestInfo } from "@playwright/test";

// Non-empty fixture with two observed paths so the security graph page can
// prove that queue selection updates the in-place graph and evidence panel.
const scanId = "scan-cockpit-fixture";
const createdAt = "2026-05-27T16:00:00Z";

async function inspectPathAssessment(detail: Locator, expected: string | RegExp) {
  const disclosure = detail.locator(".ep-header-details");
  await disclosure.locator(":scope > summary").click();
  await expect(detail.getByRole("region", { name: "Path evidence assessment" })).toContainText(expected);
  await disclosure.locator(":scope > summary").click();
}


async function visibleGraphLabelCollisions(page: Page) {
  return page.locator(".react-flow").evaluate(flow => {
    const labels = [...flow.querySelectorAll(".react-flow__edge-text, .relationship-badge")]
      .map(element => ({ text: element.textContent, rect: element.getBoundingClientRect() }));
    const nodes = [...flow.querySelectorAll(".react-flow__node")].flatMap(node => {
      const card = node.querySelector("[data-graph-entity]");
      return (card ? [...card.children] : [node]).map(content => {
        const box = content.getBoundingClientRect();
        const pad = content.classList.contains("graph-entity-glyph") ? 8 : 0;
        return { text: node.textContent, rect: new DOMRect(box.left - pad, box.top - pad, box.width + pad * 2, box.height + pad * 2) };
      }).filter(({ rect }) => rect.width > 0 && rect.height > 0);
    });
    const overlaps = (left: DOMRect, right: DOMRect) => left.left < right.right && left.right > right.left
      && left.top < right.bottom && left.bottom > right.top;
    return labels.flatMap((left, index) => [
      ...labels.slice(index + 1).filter(right => overlaps(left.rect, right.rect)).map(right => `${left.text} overlaps ${right.text}`),
      ...nodes.filter(node => overlaps(left.rect, node.rect)).map(node => `${left.text} intersects ${node.text}`),
    ]);
  });
}


type GraphNode = {
  id: string;
  entity_type: string;
  label: string;
  category_uid: number;
  class_uid: number;
  type_uid: number;
  status: string;
  risk_score: number;
  severity: string;
  severity_id: number;
  first_seen: string;
  last_seen: string;
  attributes: Record<string, unknown>;
  compliance_tags: string[];
  data_sources: string[];
  dimensions: Record<string, string>;
};

type GraphEdge = {
  id: string;
  source: string;
  target: string;
  relationship: string;
  direction: "directed" | "bidirectional";
  weight: number;
  traversable: boolean;
  first_seen: string;
  last_seen: string;
  evidence: Record<string, unknown>;
  activity_id: number;
};

function node(id: string, entityType: string, label: string, severity = "none", riskScore = 0): GraphNode {
  const severityRank: Record<string, number> = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
  return {
    id,
    entity_type: entityType,
    label,
    category_uid: 0,
    class_uid: 0,
    type_uid: 0,
    status: "active",
    risk_score: riskScore,
    severity,
    severity_id: severityRank[severity] ?? 0,
    first_seen: createdAt,
    last_seen: createdAt,
    attributes: {},
    compliance_tags: [],
    data_sources: ["scan"],
    dimensions: {},
  };
}

function edge(source: string, target: string, relationship: string, weight = 1): GraphEdge {
  return {
    id: `${source}->${target}:${relationship}`,
    source,
    target,
    relationship,
    direction: "directed",
    weight,
    traversable: true,
    first_seen: createdAt,
    last_seen: createdAt,
    evidence: { cvss_score: 9.8, epss_score: 0.71, is_kev: true },
    activity_id: 1,
  };
}

function buildCockpitGraph(nodeCount = 5) {
  const nodes: GraphNode[] = [
    node("agent:desktop", "agent", "claude-desktop"),
    node("server:github", "server", "github"),
    node("pkg:form-data", "package", "form-data@4.0.0", "critical", 9.6),
    node("cve:form-data", "vulnerability", "CVE-2025-7783", "critical", 9.8),
    node("cred:gh-token", "credential", "GITHUB_PERSONAL_ACCESS_TOKEN", "high", 7.5),
  ];
  const edges: GraphEdge[] = [
    edge("agent:desktop", "server:github", "uses"),
    edge("server:github", "pkg:form-data", "depends_on"),
    edge("pkg:form-data", "cve:form-data", "vulnerable_to", 1.5),
    edge("server:github", "cred:gh-token", "exposes_cred"),
  ];
  for (let index = nodes.length; index < nodeCount; index += 1) {
    nodes.push(node(`resource:${index}`, "cloud_resource", `production-resource-${index}`, index % 17 === 0 ? "high" : "none", index % 17 === 0 ? 7.1 : 0));
  }

  return {
    scan_id: scanId,
    tenant_id: "default",
    created_at: createdAt,
    nodes,
    edges,
    attack_paths: [
      {
        source: "agent:desktop",
        target: "cve:form-data",
        hops: ["agent:desktop", "server:github", "pkg:form-data", "cve:form-data"],
        edges: [
          "agent:desktop->server:github:uses",
          "server:github->pkg:form-data:depends_on",
          "pkg:form-data->cve:form-data:vulnerable_to",
        ],
        composite_risk: 9.8,
        summary: "claude-desktop reaches a critical vulnerable package through the github MCP server.",
        credential_exposure: ["GITHUB_PERSONAL_ACCESS_TOKEN"],
        tool_exposure: ["create_pull_request"],
        vuln_ids: ["CVE-2025-7783"],
      },
      {
        source: "agent:desktop",
        target: "cred:gh-token",
        hops: ["agent:desktop", "server:github", "cred:gh-token"],
        edges: [
          "agent:desktop->server:github:uses",
          "server:github->cred:gh-token:exposes_cred",
        ],
        composite_risk: 7.5,
        summary: "claude-desktop reaches an exposed credential through the github MCP server.",
        credential_exposure: ["GITHUB_PERSONAL_ACCESS_TOKEN"],
        tool_exposure: [],
        vuln_ids: [],
      },
    ],
    interaction_risks: [],
    stats: {
      total_nodes: nodes.length,
      total_edges: edges.length,
      node_types: { agent: 1, server: 1, package: 1, vulnerability: 1, credential: 1 },
      severity_counts: { critical: 2, high: 1, medium: 0 },
      relationship_types: { uses: 1, depends_on: 1, vulnerable_to: 1, exposes_cred: 1 },
      attack_path_count: 2,
      interaction_risk_count: 0,
      max_attack_path_risk: 9.8,
      highest_interaction_risk: 0,
    },
    pagination: { total: nodes.length, offset: 0, limit: 250, has_more: false },
  };
}

async function routeCockpit(
  page: Page,
  snapshotNodeCount?: number,
  options: {
    emptyFocusResults?: boolean;
    emptyRollup?: boolean;
    rollupDelayMs?: number;
    fixFirstDelayMs?: number;
    rollupItemCount?: number;
    qualifiedEvidence?: boolean;
    longPathNodeCount?: number;
    longNodeLabel?: boolean;
    referenceGraph?: boolean;
    scenarioTool?: boolean;
  } = {},
) {
  await page.route("**/v1/**", route => route.fulfill({ status: 404, json: { detail: "Outside graph fixture" } }));
  const graph = buildCockpitGraph(snapshotNodeCount);
  if (options.referenceGraph) {
    const reference = JSON.parse(readFileSync("../examples/reference-evidence-lab/generated/correlation-proof.json", "utf8"));
    Object.assign(graph, reference.capture_fixture.graph, { scan_id: scanId, tenant_id: "default" });
  }
  if (options.scenarioTool) {
    graph.nodes[0]!.label = "Developer Copilot";
    graph.nodes[1]!.label = "github-enterprise MCP";
    graph.nodes.push(node("tool:repo-write", "tool", "create_pull_request"));
    graph.edges.push(edge("server:github", "tool:repo-write", "provides_tool"));
    graph.stats.total_nodes = graph.nodes.length;
    graph.stats.total_edges = graph.edges.length;
    graph.pagination.total = graph.nodes.length;
  }
  if (options.longNodeLabel) graph.nodes[1]!.label = `reference-evidence-api@sha256:${"a".repeat(64)}`;
  if (options.longPathNodeCount) {
    const intermediates = Array.from({ length: options.longPathNodeCount - 3 }, (_, index) =>
      node(`server:hop-${index}`, "server", `Recorded service ${index + 1}`));
    graph.nodes = [graph.nodes[0]!, ...intermediates, graph.nodes[2]!, graph.nodes[3]!];
    graph.edges = graph.nodes.slice(1).map((item, index) => edge(graph.nodes[index]!.id, item.id, "depends_on"));
    graph.attack_paths = [{ ...graph.attack_paths[0]!, hops: graph.nodes.map(item => item.id), edges: graph.edges.map(item => item.id) }];
    graph.stats.total_nodes = graph.nodes.length;
    graph.stats.total_edges = graph.edges.length;
  }
  const baseRollupItems = [
    {
      id: "account:production",
      label: "Production account",
      entity_type: "cloud_account",
      severity: "critical",
      is_container: true,
      has_children: true,
      direct_child_count: 900,
      aggregate: {
        descendant_count: 900,
        by_type: { cloud_resource: 900 },
        severity_counts: { critical: 1, high: 53, none: 846 },
        worst_severity: "critical",
        worst_severity_rank: 4,
        internet_exposed: true,
        toxic_combo: true,
        exposed_count: 8,
        toxic_count: 1,
      },
    },
    {
      id: "account:development",
      label: "Development account",
      entity_type: "cloud_account",
      severity: "high",
      is_container: true,
      has_children: true,
      direct_child_count: 341,
      aggregate: {
        descendant_count: 341,
        by_type: { cloud_resource: 341 },
        severity_counts: { high: 20, none: 321 },
        worst_severity: "high",
        worst_severity_rank: 3,
        internet_exposed: false,
        toxic_combo: false,
        exposed_count: 0,
        toxic_count: 0,
      },
    },
  ];
  const requestedRollupItems = Math.max(2, options.rollupItemCount ?? 2);
  const rollupItems = options.emptyRollup
    ? []
    : Array.from({ length: requestedRollupItems }, (_, index) => {
        if (index < baseRollupItems.length) return baseRollupItems[index]!;
        return {
          ...baseRollupItems[1]!,
          id: `account:team-${index}`,
          label: `Team account ${index}`,
          severity: "none",
          direct_child_count: 1,
          aggregate: {
            ...baseRollupItems[1]!.aggregate,
            descendant_count: 1,
            severity_counts: { none: 1 },
            worst_severity: "none",
            worst_severity_rank: 0,
          },
        };
      });

  await page.route("**/health", async (route) => {
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ status: "ok" }) });
  });
  await page.route("**/v1/auth/me", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        authenticated: true,
        auth_required: false,
        configured_modes: [],
        recommended_ui_mode: "no_auth",
        auth_method: null,
        subject: null,
        role: null,
        role_summary: null,
        tenant_id: "default",
        memberships: [],
        request_id: "req-cockpit-e2e",
        trace_id: "trace-cockpit-e2e",
        span_id: "span-cockpit-e2e",
      }),
    });
  });
  await page.route("**/v1/posture/counts", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ critical: 2, high: 1, medium: 0, low: 0, total: 3, kev: 1, compound_issues: 1 }),
    });
  });
  // Graph-only fixtures expose their recorded snapshot through inventory too.
  // Live scan-backed current-estate reconciliation is covered separately.
  await page.route("**/v1/inventory/summary**", route => route.fulfill({ json: {
    scan_id: scanId, tenant_id: "default", total_assets: graph.nodes.length,
    evidence_scope: "historical_snapshot", snapshot_generation: "a".repeat(32),
  } }));
  await page.route("**/v1/graph/snapshots?**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify([
        {
          scan_id: scanId,
          created_at: createdAt,
          node_count: snapshotNodeCount ?? graph.nodes.length,
          edge_count: graph.edges.length,
          risk_summary: graph.stats.severity_counts,
        },
      ]),
    });
  });
  await page.route("**/v1/graph/scenarios", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        schema: "graph.scenarios.v1",
        count: 1,
        scenarios: [
          {
            scenario_id: "scenario-private-endpoint",
            tenant_id: "default",
            name: "Private service endpoint",
            description: "Replace public database access with a private endpoint.",
            base_scan_id: scanId,
            assumptions: ["The endpoint policy is deployed with least privilege."],
            changes: [],
            revision: 2,
            created_by: "analyst@example.com",
            created_at: createdAt,
            updated_at: createdAt,
          },
        ],
      }),
    });
  });
  await page.route("**/v1/graph/scenarios/scenario-private-endpoint/comparison?**", async (route) => {
    const proposedNode = node(
      "proposal:scenario-private-endpoint:private-endpoint",
      "cloud_resource",
      "Private service endpoint",
    );
    proposedNode.status = "proposed";
    proposedNode.attributes = {
      evidence_state: "proposed",
      observed: false,
      deployed: false,
      scenario_id: "scenario-private-endpoint",
      scenario_revision: 2,
      assumption: "The endpoint policy is deployed with least privilege.",
    };
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        schema: "graph.scenario-comparison.v1",
        scenario: {
          scenario_id: "scenario-private-endpoint",
          tenant_id: "default",
          name: "Private service endpoint",
          description: "Replace public database access with a private endpoint.",
          base_scan_id: scanId,
          assumptions: ["The endpoint policy is deployed with least privilege."],
          changes: [],
          revision: 2,
          created_by: "analyst@example.com",
          created_at: createdAt,
          updated_at: createdAt,
        },
        current: { scan_id: scanId, node_count: graph.nodes.length, edge_count: graph.edges.length },
        proposed: {
          node_count: graph.nodes.length + 1,
          edge_count: graph.edges.length - 1,
          modeled: true,
          nodes: [...graph.nodes, proposedNode],
          edges: graph.edges.filter((item) => item.id !== "server:github->cred:gh-token:exposes_cred"),
          completeness: { status: "complete", complete: true, sampled: false, truncated: false, returned: graph.nodes.length + 1, total: graph.nodes.length + 1 },
        },
        difference: {
          nodes_added: [proposedNode.id],
          nodes_removed: [],
          nodes_changed: ["server:github"],
          edges_added: [],
          edges_removed: ["server:github->cred:gh-token:exposes_cred"],
          touched_observed_path_count: 1,
          touched_observed_path_ids: ["agent:desktop->cred:gh-token"],
        },
        available: true,
        stale: false,
      }),
    });
  });
  await page.route("**/v1/graph/views/fix-first?**", async (route) => {
    if (options.fixFirstDelayMs) {
      await new Promise((resolve) => setTimeout(resolve, options.fixFirstDelayMs));
    }
    const attackPath = graph.attack_paths[0]!;
    const cards = options.emptyFocusResults
      ? []
      : [
          {
            id: "card-cockpit-fixture",
            rank: 1,
            title: "Critical package reachable from MCP server",
            summary: attackPath.summary,
            attack_path: attackPath,
            exposure_path: options.qualifiedEvidence ? {
              id: "qualified-path-fixture", label: "Recorded package path", summary: "Recorded relationships do not establish effective permission, exploitation or successful data access.",
              riskScore: 9.8, severity: "critical", source: { id: "agent:desktop", label: "claude-desktop", role: "agent" },
              target: { id: "cve:form-data", label: "CVE-2025-7783", role: "finding" },
              hops: attackPath.hops.map(id => graph.nodes.find(item => item.id === id)!).map(item => ({ id: item.id, label: item.label, role: item.entity_type === "vulnerability" ? "finding" : item.entity_type })),
              relationships: graph.edges.slice(0, 3), nodeIds: attackPath.hops, edgeIds: attackPath.edges,
              findings: attackPath.vuln_ids, affectedAgents: ["claude-desktop"], affectedServers: ["github"], reachableTools: [], exposedCredentials: [],
              evidenceDimensions: { reachability: { status: "unavailable", verdict: "unknown" }, exploitability: { status: "unavailable", verdict: "not_assessed" },
                impact: { status: "unavailable" }, actionability: { status: "unavailable" }, completeness: { status: "partial" } },
              provenance: { source: "fixture", scanId },
            } : undefined,
            nodes: graph.nodes,
            sequence_labels: ["claude-desktop", "github", "form-data@4.0.0", "CVE-2025-7783"],
            risk_reasons: [
              {
                kind: "critical_vulnerability",
                label: "Critical reachable CVE",
                detail: "A critical vulnerability is reachable from an agent-connected MCP server.",
              },
            ],
            next_actions: [
              {
                title: "Upgrade vulnerable package",
                detail: "Prioritize the package dependency before granting more tool access.",
                href: "/remediation",
              },
            ],
            affected: {
              agents: ["claude-desktop"],
              servers: ["github"],
              packages: ["form-data@4.0.0"],
              findings: ["CVE-2025-7783"],
              credentials: ["GITHUB_PERSONAL_ACCESS_TOKEN"],
              tools: ["create_pull_request"],
            },
          },
        ];
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        scan_id: scanId,
        tenant_id: "default",
        created_at: createdAt,
        cards,
        summary: {
          total_paths: 1,
          matched_paths: cards.length,
          returned_paths: cards.length,
          highest_risk: cards.length ? 9.8 : 0,
          covered_findings: cards.length,
          node_count: graph.nodes.length,
          edge_count: graph.edges.length,
        },
        focus: { cve: "", package: "", agent: "" },
      }),
    });
  });
  await page.route("**/v1/graph/attack-paths?**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ...graph,
        pagination: { total: graph.attack_paths.length, offset: 0, limit: 100, has_more: false },
        completeness: { returned: graph.attack_paths.length, total: graph.attack_paths.length, truncated: false, reason: "" },
        count_metadata: {
          source: "persisted_graph_paths",
          snapshot_total: graph.attack_paths.length,
          materialized_paths: graph.attack_paths.length,
          derived_paths: 0,
          returned_rows: graph.attack_paths.length,
        },
      }),
    });
  });
  await page.route("**/v1/graph/diff?**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ nodes_added: [], nodes_removed: [], nodes_changed: [], edges_added: [], edges_removed: [] }),
    });
  });
  await page.route("**/v1/graph?**", async (route) => {
    await route.fulfill({ contentType: "application/json", body: JSON.stringify(graph) });
  });
  await page.route("**/v1/graph/rollup?**", async (route) => {
    if (options.rollupDelayMs) {
      await new Promise((resolve) => setTimeout(resolve, options.rollupDelayMs));
    }
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        scan_id: scanId,
        tenant_id: "default",
        created_at: createdAt,
        mode: "rollup",
        filters: {},
        top_level: rollupItems,
        // The server aggregates every non-containment edge onto the containers
        // its endpoints roll up into, so a collapsed estate arrives as a
        // topology. This fixture used to omit the key entirely, which made the
        // canvas draw a grid of disconnected cards and let an "edge-free
        // roll-up" assertion look like a deliberate decision rather than a
        // fixture that could not have shown an edge either way.
        edges: options.emptyRollup ? [] : [
          {
            source: "account:development",
            target: "account:production",
            count: 35,
            relationships: ["can_access", "uses"],
          },
        ],
        completeness: {
          returned: rollupItems.length,
          total: rollupItems.length,
          truncated: false,
          reason: "",
        },
        edge_count_metadata: {
          definition: "aggregated non-containment relationship rows between returned containers",
          source_total: options.emptyRollup ? 0 : 1,
          returned: options.emptyRollup ? 0 : 1,
          truncated: false,
          source_truncated: false,
          reason: "",
        },
        summary: {
          total_nodes: snapshotNodeCount ?? 1241,
          total_edges: graph.edges.length,
          top_level_count: rollupItems.length,
          container_count: rollupItems.length,
        },
      }),
    });
  });
}

for (const proof of [
  { theme: "dark", width: 1512, height: 811 },
  { theme: "light", width: 1568, height: 780 },
] as const) {
  for (const capture of [false, true]) {
  test(`scenario comparison stays truthful at ${proof.width}x${proof.height} ${proof.theme} capture=${capture}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: proof.width, height: proof.height });
    await routeCockpit(page, 36, { scenarioTool: true });
    await page.addInitScript((selectedTheme) => {
      window.localStorage.setItem("agent-bom-theme", selectedTheme);
    }, proof.theme);

    await page.goto(`/security-graph?lens=estate&rollup=0&scenario=scenario-private-endpoint&state=proposed${capture ? "&capture=1" : ""}`);
    await page.waitForLoadState("networkidle");
    await expect(page.getByRole("status")).toContainText(
      "Proposed scenario — not observed or deployed",
    );
    await expect(page.getByRole("group", { name: "Investigation view" })).toBeHidden();
    await expect(page.getByText("Current · observed")).toBeVisible();
    await expect(page.getByText("Proposed · modeled")).toBeVisible();
    const canvas = page.locator(".react-flow");
    const unconnected = page.getByRole("region", { name: "Unconnected proposal items" });
    await expect(unconnected).toBeVisible();
    await expect(unconnected.getByRole("button", { name: /Private service endpoint/ })).toBeVisible();
    await expect(canvas.locator('[data-id="proposal:scenario-private-endpoint:private-endpoint"]')).toHaveCount(0);
    await expect(canvas.locator('[data-id="cred:gh-token"]')).toHaveCount(0);
    await expect(canvas.locator('.react-flow__edge[data-id="server:github->cred:gh-token:exposes_cred"]')).toHaveCount(0);
    // Zoom-aware typography can remain readable below the former fixed 0.75
    // zoom floor. Assert actual rendered text size and containment below.
    const canvasBox = await canvas.boundingBox();
    expect(canvasBox).not.toBeNull();
    expect(canvasBox!.height).toBeGreaterThanOrEqual(240);
    expect(canvasBox!.y + canvasBox!.height).toBeLessThanOrEqual(proof.height + 16);
    await expect.poll(() => canvas.evaluate(flow => {
      const frame = flow.getBoundingClientRect();
      const controls = flow.querySelector(".react-flow__controls")!.getBoundingClientRect();
      const zoom = new DOMMatrixReadOnly(getComputedStyle(flow.querySelector(".react-flow__viewport")!).transform).a;
      const nodes = [...flow.querySelectorAll(".react-flow__node")];
      return nodes.flatMap(node => {
        const box = node.getBoundingClientRect();
        const overlap = box.left < controls.right && box.right > controls.left && box.top < controls.bottom && box.bottom > controls.top;
        const text = [...node.querySelectorAll("p, span")].filter(el => el.textContent?.trim() && !el.querySelector("p, span"));
        const issues = [];
        if (box.left < frame.left || box.right > frame.right || box.top < frame.top || box.bottom > frame.bottom) issues.push(`Clipped: ${node.textContent}`);
        if (overlap) issues.push(`Controls overlap: ${node.textContent}`);
        for (const el of text) if (parseFloat(getComputedStyle(el).fontSize) * zoom < 12 - 0.01) issues.push(`Small text: ${el.textContent} (${parseFloat(getComputedStyle(el).fontSize) * zoom}px)`);
        return issues;
      });
    })).toEqual([]);
    const labelCollisions = await visibleGraphLabelCollisions(page);
    expect(labelCollisions).toEqual([]);
    await expect(canvas.locator(".react-flow__node")).toHaveCount(4);
    await page.screenshot({ path: testInfo.outputPath(`scenario-first-view-${proof.theme}-${capture}.png`) });
    await expect.poll(() => canvas.locator(".react-flow__node").evaluateAll((nodes) => {
      const frame = nodes[0]?.closest(".react-flow")?.getBoundingClientRect();
      if (!frame) return 0;
      return nodes.filter((node) => {
        const box = node.getBoundingClientRect();
        return box.left >= frame.left && box.right <= frame.right && box.top >= frame.top && box.bottom <= frame.bottom;
      }).length;
    })).toBeGreaterThanOrEqual(3);
    await expect(unconnected).toContainText("Connection removed in proposal");
    await expect(unconnected).toContainText("No connection in supplied proposal");
    await expect(page.getByTestId("scenario-impact-summary")).toContainText("Observed paths touched");
    await expect(page.getByTestId("graph-viewport-scope")).toContainText("Fit all");
    await expect(page.getByTestId("graph-viewport-scope")).toContainText("Changes and neighbors");
    await page.getByRole("button", { name: "Show full graph" }).click();
    await expect(page.getByRole("button", { name: "Focus changes" })).toBeVisible();
    await expect(canvas.locator('[data-id="cred:gh-token"]')).toHaveCount(0);
    await expect(unconnected).toBeVisible();
    await expect(page.getByTestId("graph-viewport-scope")).not.toContainText("Changes and neighbors");
    await page.getByRole("button", { name: "Focus changes" }).click();
    await expect(page.getByTestId("graph-viewport-scope")).toContainText("Changes and neighbors");
    await unconnected.getByRole("button", { name: /Private service endpoint/ }).click();
    await expect(page.getByTestId("graph-drawer-tab-overview")).toBeVisible();
    await page.getByRole("button", { name: "Close", exact: true }).click();
    await page.getByRole("button", { name: "Review modeled changes" }).click();
    await expect(page).toHaveURL(/state=difference/);
    await expect(page.getByTestId("graph-scenario-difference")).toContainText(
      "1 touched observed paths",
    );
    const overflows = await page.evaluate(
      () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
    );
  expect(overflows).toBe(false);
    await page.screenshot({
      path: testInfo.outputPath(`graph-scenario-${proof.width}x${proof.height}-${proof.theme}.png`),
      fullPage: true,
    });
  });
  }
}

test("Attack Paths keeps scenario state observed-only", async ({ page }) => {
  await routeCockpit(page);
  await page.goto(`/security-graph?lens=attack-path&scenario=scenario-private-endpoint&state=proposed`);
  await page.waitForLoadState("networkidle");

  await expect(page.getByText(/Attack Paths remains observed-only/)).toBeVisible();
  await expect(page.getByText(/Proposed scenario — not observed or deployed/)).toHaveCount(0);
  await expect(page).toHaveURL(/state=current/);
});

async function openPathQueue(page: Page) {
  await expect(page.getByRole("region", { name: "Investigation workspace" })).toBeVisible();
  const queue = page.locator("#investigation-queue");
  if ((page.viewportSize()?.width ?? 1440) < 1024) {
    await page.getByRole("button", { name: /^Paths & filters/ }).click();
  } else if (await queue.getAttribute("open") === null) {
    await queue.locator(":scope > summary").click();
  }
  await expect(queue).toHaveAttribute("open");
}

async function expectCockpitVisible(page: Page) {
  await expect(page.getByRole("heading", { name: "Investigation" })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Claude Desktop → CVE-2025-7783" }),
  ).toBeVisible();
  // Progressive disclosure summary — avoid /Evidence/ which also matches "Evidence drawer".
  await expect(page.getByText("Evidence & relationships")).toBeVisible();
  await expect(page.getByText("Path priority", { exact: true }).first()).toBeHidden();
  await page.locator(".ep-header-summary").click();
  await expect(page.getByText("Path priority", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Path span", { exact: true }).first()).toBeVisible();
}

for (const theme of ["dark", "light"] as const) {
  test(`security-graph cockpit ${theme} renders exposure command center on a non-empty graph`, async ({ page }, testInfo: TestInfo) => {
    await routeCockpit(page);
    await page.addInitScript((selectedTheme) => {
      window.localStorage.setItem("agent-bom-theme", selectedTheme);
    }, theme);

    await page.goto("/security-graph?lens=attack-path");
    await page.waitForLoadState("networkidle");
    await expectCockpitVisible(page);

    await page.screenshot({ path: testInfo.outputPath(`security-graph-cockpit-${theme}.png`), fullPage: true });
  });
}

test("security-graph cockpit stays usable on a mobile viewport", async ({ page }, testInfo: TestInfo) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await routeCockpit(page);

  await page.goto("/security-graph?lens=attack-path");
  await page.waitForLoadState("networkidle");
  await expectCockpitVisible(page);
  const overflows = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  expect(overflows).toBe(false);

  await page.screenshot({ path: testInfo.outputPath("security-graph-cockpit-mobile.png"), fullPage: true });
});

test("requested scan without a graph snapshot never falls back to another scan", async ({ page }) => {
  await routeCockpit(page);

  const requestedScopes: string[] = [];
  // A retained historical scan can fall outside the snapshot selector's page.
  // Resolve it through the API; an actual missing scan returns 404.
  for (const endpoint of ["attack-paths", "views/fix-first"]) {
    await page.route(`**/v1/graph/${endpoint}?**`, route => {
      requestedScopes.push(new URL(route.request().url()).searchParams.get("scan_id") ?? "");
      return route.fulfill({ status: 404, json: { detail: "Graph snapshot not found" } });
    });
  }
  await page.goto("/security-graph?lens=attack-path&scan=scan-without-graph&cve=CVE-2099-MISSING");
  await expect(page.getByText("Cannot load attack paths for this snapshot")).toBeVisible();
  expect(requestedScopes.length).toBeGreaterThan(0);
  expect(requestedScopes.every(scope => scope === "scan-without-graph")).toBe(true);
  await expect(page.getByRole("heading", { name: "Claude Desktop → CVE-2025-7783" })).toHaveCount(0);
});

test("focused investigation never shows an unrelated global path", async ({ page }) => {
  await routeCockpit(page, undefined, { emptyFocusResults: true });

  await page.goto(`/security-graph?scan=${scanId}&cve=CVE-2099-NOT-IN-SNAPSHOT`);
  await page.waitForLoadState("networkidle");

  await expect(page.getByText("No attack paths matched the current focus")).toBeVisible();
  await expect(page.getByText(/This does not establish whether the vulnerability is exploitable/)).toBeVisible();
  await expect(page.getByRole("heading", { name: "Claude Desktop → CVE-2025-7783" })).toHaveCount(0);
});

test("unlinked finding records require an explicit move to related package paths", async ({ page }) => {
  await routeCockpit(page);
  await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&node=pkg%3Aform-data&cve=CVE-2025-7783&package=form-data&finding=unlinked-record`);
  await expect(page.getByText("No path is linked to this finding record")).toBeVisible();
  await page.getByRole("link", { name: "Show related package and advisory paths" }).click();
  await expect(page.getByRole("note", { name: "Finding association" })).toContainText("does not establish a link to the selected finding record");
  await expect(page.getByRole("heading", { name: "Claude Desktop → CVE-2025-7783" })).toBeVisible();
  expect(new URL(page.url()).searchParams.get("scan")).toBe(scanId);
  expect(new URL(page.url()).searchParams.get("node")).toBe("pkg:form-data");
  expect(new URL(page.url()).searchParams.has("finding")).toBe(false);
});

test("snapshot loading never claims that an empty graph loaded successfully", async ({ page }) => {
  await routeCockpit(page);
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  await page.route("**/v1/graph/snapshots?**", async route => { await pending; await route.fallback(); });
  try {
    await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&cve=CVE-2025-7783`);
    await expect(page.getByRole("heading", { name: "Loading security graph" })).toBeVisible();
    await expect(page.getByText(/The persisted graph loaded successfully/)).toHaveCount(0);
  } finally {
    release();
  }
});

test("ranked persisted paths render before slower fix guidance", async ({ page }) => {
  await routeCockpit(page, undefined, { fixFirstDelayMs: 2_000 });

  await page.goto("/security-graph?lens=attack-path");
  await openPathQueue(page);
  await expect(page.getByText("#1 fix first")).toBeVisible();
  await expect(page.getByText(/Ranked paths are ready; fix guidance is still loading/)).toBeVisible();
  await expect(page.getByText("agent → server → package → finding")).toBeVisible();

  await expect(page.getByRole("heading", { name: "Claude Desktop → CVE-2025-7783" })).toBeVisible();
});

test("top-path deep links settle and keep subsequent queue selection interactive", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error" && /Maximum update depth/.test(message.text())) errors.push(message.text());
  });
  await routeCockpit(page);
  await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&path=top`);
  const detail = page.getByTestId("selected-exposure-path");
  await expect(detail.getByRole("heading", { name: "Claude Desktop → CVE-2025-7783" })).toBeVisible();
  await expect(detail.getByTestId("exposure-path-primary-action")).toHaveAttribute(
    "href", `/remediation?scan=${scanId}&cve=CVE-2025-7783&package=form-data%404.0.0`,
  );
  await openPathQueue(page);
  await page.getByLabel("Attack path queue").getByRole("button", { name: /#2/ }).click();
  await expect(page.getByRole("status")).toContainText("Focused path 2");
  // Let post-selection effects settle before checking that focus stays put.
  await page.waitForTimeout(500);
  await expect(page.getByRole("status")).toContainText("Focused path 2");
  await expect(detail).toBeVisible();
  expect(errors).toEqual([]);
});

test("ranked path selection opens the ordered path and can expand the interactive graph", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await routeCockpit(page);

  await page.goto("/security-graph?lens=attack-path");
  await page.waitForLoadState("networkidle");

  const workspace = page.getByRole("region", { name: "Investigation workspace" });
  await openPathQueue(page);
  const queue = workspace.getByLabel("Attack path queue");
  const detail = workspace.getByRole("region", { name: "Selected path detail" });
  const [queueBox, detailBox] = await Promise.all([workspace.locator(".investigation-queue").boundingBox(), detail.boundingBox()]);
  expect(queueBox).not.toBeNull();
  expect(detailBox).not.toBeNull();
  expect(Math.abs(queueBox!.y - detailBox!.y)).toBeLessThan(200);

  await queue.getByRole("button", { name: /#2/ }).click();
  await expect(detail.getByRole("button", { name: "Graph", exact: true })).toHaveAttribute("aria-pressed", "true");
  await detail.getByRole("button", { name: "Graph", exact: true }).click();
  await expect(detail.getByTestId("security-graph-investigation")).toBeVisible();
  await expect(page.getByRole("status")).toContainText("Focused path 2");
  const [selectedRowBox, focusedDetailBox] = await Promise.all([
    queue.getByRole("button", { name: /#2/ }).boundingBox(),
    detail.boundingBox(),
  ]);
  expect(selectedRowBox).not.toBeNull();
  expect(focusedDetailBox).not.toBeNull();
  expect(selectedRowBox!.y).toBeLessThan(1000);
  expect(focusedDetailBox!.y).toBeLessThan(1000);
});

for (const theme of ["light", "dark"] as const) {
  test(`selected graph refits after its desktop queue changes canvas width ${theme}`, async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await routeCockpit(page);
    await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&path=top`);
    await openPathQueue(page);
    await page.getByLabel("Attack path queue").getByRole("button", { name: /#2/ }).click();
    const graph = page.getByTestId("security-graph-investigation").locator(".react-flow");
    await expect(graph.locator(".react-flow__node")).toHaveCount(3);
    for (const width of [1440, 1280]) {
      await page.setViewportSize({ width, height: 1000 });
      await expect.poll(() => graph.evaluate(canvas => {
        const viewport = canvas.getBoundingClientRect();
        return [...canvas.querySelectorAll(".react-flow__node")].every(node => {
          const box = node.getBoundingClientRect();
          return box.left >= viewport.left - 2 && box.right <= viewport.right + 2
            && box.top >= viewport.top - 2 && box.bottom <= viewport.bottom + 2;
        });
      })).toBe(true);
    }
    const box = await graph.boundingBox();
    const viewport = graph.locator(".react-flow__viewport");
    const beforePan = await viewport.getAttribute("style");
    await page.mouse.move(box!.x + 100, box!.y + box!.height - 60);
    await page.mouse.down();
    await page.mouse.move(box!.x + 150, box!.y + box!.height - 60, { steps: 5 });
    await page.mouse.up();
    await expect(viewport).not.toHaveAttribute("style", beforePan!);
    const pinned = await viewport.getAttribute("style");
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.waitForTimeout(500);
    await expect(viewport).toHaveAttribute("style", pinned!);
  });
}

for (const theme of ["light", "dark"] as const) {
test(`mobile ranked path selection moves the ordered path into view ${theme}`, async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.addInitScript((value) => window.localStorage.setItem("agent-bom-theme", value), theme);
  await routeCockpit(page);

  await page.goto("/security-graph?lens=attack-path");
  await page.waitForLoadState("networkidle");

  await page.getByRole("button", { name: /Paths & filters/ }).click();
  // Selecting an already loaded path is local state: a route navigation must
  // not replace its document or reset the viewport while sharing the URL.
  const selectionNavigations: string[] = [];
  await page.route("**/security-graph?**", async route => {
    if (route.request().headers()["rsc"] || route.request().isNavigationRequest()) {
      selectionNavigations.push(route.request().url());
    }
    await route.continue();
  });
  await openPathQueue(page);
  const queue = page.getByLabel("Attack path queue");
  await queue.getByRole("button", { name: /#2/ }).click();
  const detail = page.getByRole("region", { name: "Selected path detail" });
  await expect(detail.getByRole("button", { name: "Graph", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect.poll(async () => (await detail.boundingBox())?.y ?? Number.POSITIVE_INFINITY).toBeLessThan(120);
  await expect(page).toHaveURL(/selected_path=/);
  await page.waitForLoadState("networkidle");
  expect(selectionNavigations).toEqual([]);
  await expect.poll(async () => (await detail.boundingBox())?.y ?? Number.POSITIVE_INFINITY).toBeLessThan(120);
  await page.screenshot({ path: testInfo.outputPath(`selected-path-${theme}.png`) });
});
}

test("priority enrichment cannot replace or inflate the authoritative path queue", async ({ page }) => {
  await routeCockpit(page);
  const graph = buildCockpitGraph();
  const extra = { ...graph.attack_paths[0]!, source: "repo:outside", hops: ["repo:outside", "ci:outside"] };
  await page.route("**/v1/graph/views/fix-first?**", route => route.fulfill({ json: {
    scan_id: scanId, tenant_id: "default", created_at: createdAt, attack_campaigns: [],
    summary: { total_paths: 3, matched_paths: 3, returned_paths: 1, highest_risk: 99, covered_findings: 0, node_count: 2, edge_count: 1 },
    focus: { cve: "", package: "", agent: "" },
    cards: [{ id: "outside", rank: 1, title: "Outside queue", summary: "Separate enrichment",
      attack_path: extra, nodes: [node("repo:outside", "directory", "Outside repository"), node("ci:outside", "ci_job", "Outside build")],
      sequence_labels: [], risk_reasons: [], next_actions: [],
      affected: { agents: [], servers: [], packages: [], findings: [], credentials: [], tools: [] } }],
  } }));
  await page.goto("/security-graph?lens=attack-path");
  await page.waitForLoadState("networkidle");
  await openPathQueue(page);
  await page.getByText("Queue coverage", { exact: true }).click();
  await expect(page.getByText("2 shown · 2 loaded paths", { exact: true })).toBeVisible();
  await openPathQueue(page);
  const queue = page.getByLabel("Attack path queue");
  await expect(queue.getByText("Outside repository", { exact: false })).toHaveCount(0);
  await queue.getByRole("button", { name: /#1 FIX FIRST/i }).click();
  const detail = page.getByRole("region", { name: "Selected path detail" });
  await expect(detail).toContainText("claude-desktop");
  await expect(detail).not.toContainText("Outside repository");
});

for (const theme of ["light", "dark"] as const) {
for (const width of [1440, 390]) {
test(`a selected queue path missing from the canvas loads its exact graph in ${theme} at ${width}px`, async ({ page }, testInfo) => {
  await page.setViewportSize({ width, height: width < 640 ? 844 : 960 });
  await page.addInitScript((value) => window.localStorage.setItem("agent-bom-theme", value), theme === "light" ? "dark" : "light");
  await routeCockpit(page);
  const source = node("repo:isolated", "directory", "Isolated repository");
  const target = node("ci:isolated", "ci_job", "Isolated build");
  const path = { ...buildCockpitGraph().attack_paths[0]!, source: source.id, target: target.id,
    hops: [source.id, target.id], edges: ["contains"], vuln_ids: [] };
  await page.route("**/v1/graph/views/fix-first?**", route => route.fulfill({ json: {
    scan_id: scanId, tenant_id: "default", created_at: createdAt, attack_campaigns: [],
    summary: { total_paths: 3, matched_paths: 3, returned_paths: 1, highest_risk: 9.8, covered_findings: 0, node_count: 7, edge_count: 5 },
    focus: { cve: "", package: "", agent: "" },
    cards: [{ id: "isolated", rank: 1, title: "Isolated build path", summary: "Recorded build relationship",
      attack_path: path, nodes: [source, target], sequence_labels: [], risk_reasons: [], next_actions: [],
      affected: { agents: [], servers: [], packages: [], findings: [], credentials: [], tools: [] } }],
  } }));
  // Keep selection authoritative while exercising hydration of absent canvas nodes.
  await page.route("**/v1/graph/attack-paths?**", route => route.fulfill({ json: {
    ...buildCockpitGraph(), attack_paths: [path, buildCockpitGraph().attack_paths[0]],
    pagination: { total: 2, offset: 0, limit: 100, has_more: false },
  } }));
  const queries: Record<string, unknown>[] = [];
  await page.route("**/v1/graph/query", (route) => {
    queries.push(route.request().postDataJSON());
    return route.fulfill({ json: { ...buildCockpitGraph(), nodes: [source, target],
      edges: [edge(source.id, target.id, "contains")], attack_paths: [], truncated: width < 640, missing_roots: [] } });
  });
  await page.goto("/security-graph?lens=attack-path");
  await page.getByRole("button", { name: `Switch to ${theme} theme`, exact: true }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
  if (width < 1024) await page.getByRole("button", { name: /Paths & filters/ }).click();
  await openPathQueue(page);
  await page.getByLabel("Attack path queue").getByRole("button", { name: /#1 FIX FIRST/i }).click();
  const detail = page.getByRole("region", { name: "Selected path detail" });
  await page.waitForLoadState("networkidle");
  const viewNavigations: string[] = [];
  page.on("request", request => {
    if (request.isNavigationRequest() || request.url().includes("_rsc=")) viewNavigations.push(request.url());
  });
  await detail.getByRole("button", { name: "Graph", exact: true }).click();
  await expect(page).toHaveURL(/path_view=graph/);
  await page.waitForLoadState("networkidle");
  expect(viewNavigations).toEqual([]);
  const canvas = detail.getByTestId("security-graph-investigation");
  await expect(canvas.locator(".react-flow__node")).toHaveCount(2);
  await expect(canvas.locator(".react-flow__edge")).toHaveCount(1);
  await expect(canvas.getByText("Isolated repository", { exact: true })).toBeVisible();
  await expect(canvas.getByText("Isolated build", { exact: true })).toBeVisible();
  await expect(canvas.getByText("claude-desktop", { exact: true })).toHaveCount(0);
  if (width < 640) {
    await expect(detail).toContainText("Selected path loaded. Broader context was limited by the graph query budget.");
    // A short path is shown whole on a phone: no stepper, every hop readable inside the canvas.
    await expect(canvas.getByRole("button", { name: "Next graph node" })).toHaveCount(0);
    const inCanvas = (id: string) => canvas.locator(`.react-flow__node[data-id="${id}"]`).evaluate(element => {
      const box = element.getBoundingClientRect();
      const frame = element.closest(".react-flow")!.getBoundingClientRect();
      return box.width >= 180 && box.left >= frame.left && box.right <= frame.right && box.top >= frame.top && box.bottom <= frame.bottom;
    });
    for (const id of [source.id, target.id]) await expect.poll(() => inCanvas(id)).toBe(true);
  }
  // Narrow panels start with readable node focus; the explicit overview still
  // has to frame every hydrated hop without loading unrelated topology.
  await canvas.locator(".react-flow__controls-fitview").click();
  await expect.poll(async () => {
    const bounds = await canvas.boundingBox();
    if (!bounds) return false;
    const boxes = await Promise.all((await canvas.locator(".react-flow__node").all()).map((node) => node.boundingBox()));
    return boxes.every((box) => box && box.x >= bounds.x && box.x + box.width <= bounds.x + bounds.width);
  }).toBe(true);
  expect(queries).toHaveLength(1);
  expect(queries[0]).toMatchObject({ roots: [source.id, target.id], scan_id: scanId, max_nodes: 2, max_depth: 1, include_attack_paths: false });
  await page.screenshot({ path: testInfo.outputPath(`selected-path-${theme}-${width}.png`), fullPage: true });
});
}
}

async function openEvidenceControls(page: Page) {
  const toggle = page.getByRole("button", { name: "View & layers", exact: true });
  if (await toggle.getAttribute("aria-expanded") !== "true") await toggle.click();
  const controls = page.getByTestId("graph-evidence-controls");
  await expect(controls).toBeVisible();
  return controls;
}

for (const theme of ["dark", "light"] as const) {
test(`large estates lead with non-overlapping clusters in ${theme}`, async ({ page }, testInfo: TestInfo) => {
  await routeCockpit(page, 1_241);
  await page.addInitScript((selectedTheme) => {
    window.localStorage.setItem("agent-bom-theme", selectedTheme);
  }, theme);

  await page.goto("/security-graph?lens=attack-path");
  await page.waitForLoadState("networkidle");

  await page.getByText("Investigation tools · snapshots, correlation & checks", { exact: true }).click();
  await expect(page.getByRole("button", { name: "Evidence scope" })).toHaveAttribute("aria-pressed", "true");
  await expect(
    page.getByText("1,241 nodes. Use a focused lens before opening the full topology."),
  ).toBeVisible();
  await expect(page.getByRole("link", { name: "Explore clusters" })).toHaveAttribute(
    "href",
    "/security-graph?scan=scan-cockpit-fixture&lens=lineage&rollup=1",
  );
  await expect(page.getByRole("link", { name: "Open raw topology" })).toHaveAttribute(
    "href",
    "/security-graph?scan=scan-cockpit-fixture&lens=lineage&rollup=0",
  );
  await page.screenshot({ path: testInfo.outputPath(`investigation-large-estate-${theme}.png`), fullPage: true });

  const rollupRequest = page.waitForRequest((request) => request.url().includes("/v1/graph/rollup"));
  await page.getByRole("link", { name: "Explore clusters" }).click();
  await expect(page).toHaveURL(/scan=scan-cockpit-fixture/);
  await expect(page).toHaveURL(/rollup=1/);
  await rollupRequest;
  await openEvidenceControls(page);
  await expect(page.getByText("Scope navigation", { exact: true })).toBeVisible();
  // Aggregated scope navigation must retain the actual relationship edge.
  await expect(page.locator(".react-flow__edge")).toHaveCount(1);
  await expect(page.getByTestId("graph-compression-summary")).toHaveCount(0);
  await expect(page.getByText(/2 nodes and scopes at this level.*1241 nodes in snapshot/)).toBeVisible();
  const cards = page.locator('[data-rollup-container="true"]');
  await expect(cards).toHaveCount(2);
  const [firstBox, secondBox] = await Promise.all([cards.nth(0).boundingBox(), cards.nth(1).boundingBox()]);
  expect(firstBox).not.toBeNull();
  expect(secondBox).not.toBeNull();
  expect(firstBox!.x + firstBox!.width).toBeLessThanOrEqual(secondBox!.x);
  await page.screenshot({ path: testInfo.outputPath(`investigation-large-estate-clustered-${theme}.png`), fullPage: true });

  await page.getByRole("button", { name: "Open node view" }).click();
  await expect(page).toHaveURL(/rollup=0/);
});
}

test("36-node snapshots default to real topology and forced roll-up still draws relationships", async ({ page }) => {
  await routeCockpit(page, 36);

  await page.goto(`/graph?scan=${scanId}`);
  await page.waitForLoadState("networkidle");
  await expect(page.getByText("Scope navigation", { exact: true })).toHaveCount(0);
  expect(await page.locator(".react-flow__edge").count()).toBeGreaterThan(0);

  await page.goto(`/graph?scan=${scanId}&rollup=1`);
  await page.waitForLoadState("networkidle");
  await openEvidenceControls(page);
  await expect(page.getByText("Scope navigation", { exact: true })).toBeVisible();
  await expect(page.locator('[data-rollup-container="true"]')).toHaveCount(2);
  // Collapsing the estate changes what a relationship is drawn *between*, never
  // whether one is drawn. A roll-up with no edges is the grid of disconnected
  // cards this view was built to stop being.
  await expect(page.locator(".react-flow__edge")).toHaveCount(1);
  await expect(page.getByTestId("graph-compression-summary")).toHaveCount(0);
});

test("200-node snapshots default to roll-up and explicit raw topology persists", async ({ page }) => {
  await routeCockpit(page, 200);

  await page.goto(`/graph?scan=${scanId}`);
  await page.waitForLoadState("networkidle");
  await openEvidenceControls(page);
  await expect(page.getByText("Scope navigation", { exact: true })).toBeVisible();
  await expect(page.getByText("2 nodes and scopes at this level · 200 nodes in snapshot", { exact: true })).toBeVisible();

  await page.goto(`/graph?scan=${scanId}&rollup=0`);
  await page.waitForLoadState("networkidle");
  await expect(page).toHaveURL(/rollup=0/);
  await expect(page.getByText("Scope navigation", { exact: true })).toHaveCount(0);
  expect(await page.locator(".react-flow__edge").count()).toBeGreaterThan(0);
});

test("empty forced roll-up preserves operator preference and falls back to real topology", async ({ page }) => {
  await routeCockpit(page, 36, { emptyRollup: true });

  await page.goto(`/graph?scan=${scanId}&rollup=1`);
  await page.waitForLoadState("networkidle");
  await expect(page).toHaveURL(/rollup=1/);
  await openEvidenceControls(page);
  await expect(page.getByText(/Roll-up unavailable/i)).toBeVisible();
  expect(await page.locator(".react-flow__edge").count()).toBeGreaterThan(0);
});

test("eligible roll-up shows a loading surface without raw-topology counts", async ({ page }) => {
  await routeCockpit(page, 200, { rollupDelayMs: 3_000 });

  await page.goto(`/graph?scan=${scanId}`);
  await openEvidenceControls(page);
  await expect(page.getByText("Loading scope navigation")).toBeVisible();
  await expect(page.getByTestId("graph-compression-summary")).toHaveCount(0);
  await expect(page.locator(".react-flow__edge")).toHaveCount(0);
  await expect(page.getByText("Scope navigation", { exact: true })).toBeVisible();
});

test("ranked paths reach the first viewport instead of sitting under a tower of bands", async ({ page }) => {
  // The investigation page stacked eight full-width bands above the content:
  // title, lens row, investigation loop, deploy gate, exposure paths, snapshot,
  // large-estate notice, metric tiles. The graph and the ranked paths — the
  // reason the page exists — began below the fold on a 900px-tall viewport.
  //
  // Controls recede, content is the hero. This pins that the paths panel starts
  // within the first viewport at a standard desktop height.
  await page.setViewportSize({ width: 1440, height: 900 });
  await routeCockpit(page);

  await page.goto("/security-graph?lens=attack-path");
  await page.waitForLoadState("networkidle");

  const paths = page.getByTestId("selected-exposure-path");
  await expect(paths).toBeVisible();
  await expect(page.getByText("Browse 2 paths & filters", { exact: true })).toBeVisible();
  const box = await paths.boundingBox();
  expect(box).not.toBeNull();
  expect(box!.y).toBeLessThan(900);
});

for (const proof of [
  { width: 1512, height: 811, theme: "light" },
  { width: 1568, height: 780, theme: "dark" },
] as const) {
  test(`estate canvas is the truthful first view at ${proof.width}x${proof.height}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: proof.width, height: proof.height });
    await routeCockpit(page, 1_241, { rollupItemCount: 30 });
    await page.addInitScript((theme) => {
      window.localStorage.setItem("agent-bom-theme", theme);
    }, proof.theme);

    await page.goto("/security-graph?lens=estate");
    await page.waitForLoadState("networkidle");

    await expect(page.getByRole("heading", { name: "Investigation", exact: true })).toBeVisible();
    const evidenceControls = page.getByTestId("graph-evidence-controls");
    await expect(page.getByRole("button", { name: "View & layers" })).toBeVisible();
    await expect(evidenceControls).toHaveCount(0);
    await expect(page.getByTestId("graph-rollup-decision-surface")).toBeVisible();
    await expect(page.getByTestId("graph-rollup-relationship-completeness")).toHaveText(
      "1 aggregated relationship rows · complete for this scope",
    );
    await expect(page.getByText("Agent Mesh")).toBeHidden();
    await expect(page.getByText("Context", { exact: true })).toBeHidden();

    const proofState = await page.evaluate(() => ({
      horizontalOverflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
      viewport: { width: window.innerWidth, height: window.innerHeight },
    }));
    expect(proofState.horizontalOverflow).toBe(false);
    expect(proofState.viewport).toEqual({ width: proof.width, height: proof.height });

    await page.screenshot({
      path: testInfo.outputPath(`investigation-canvas-estate-${proof.width}x${proof.height}.png`),
      fullPage: false,
    });
  });
}

for (const viewport of [
  { width: 1512, height: 811 },
  { width: 1568, height: 780 },
] as const) {
  test(`investigation canvas preserves evidence and saved viewport at ${viewport.width}x${viewport.height}`, async ({ page }, testInfo) => {
    await page.setViewportSize(viewport);
    await routeCockpit(page);

    await page.goto("/security-graph?lens=attack-path");
    await page.waitForLoadState("networkidle");
    await openPathQueue(page);
    await page.getByLabel("Attack path queue").getByRole("button", { name: /#1/ }).click();
    const detail = page.getByRole("region", { name: "Selected path detail" });
    await detail.getByRole("button", { name: "Graph", exact: true }).click();
    const canvas = detail.getByTestId("security-graph-investigation");
    const legendBand = detail.getByTestId("security-graph-legend-band");
    const interactionBand = detail.getByTestId("security-graph-interaction-band");
    const nodeBand = canvas.locator(".react-flow");
    await expect(canvas).toBeVisible();
    await expect(legendBand).toBeVisible();
    await expect(interactionBand).toBeVisible();
    await expect(canvas.locator(".react-flow__node")).not.toHaveCount(0);

    const [legendBox, canvasBox, interactionBox, nodeBandBox] = await Promise.all([
      legendBand.boundingBox(),
      canvas.boundingBox(),
      interactionBand.boundingBox(),
      nodeBand.boundingBox(),
    ]);
    expect(legendBox).not.toBeNull();
    expect(canvasBox).not.toBeNull();
    expect(interactionBox).not.toBeNull();
    expect(nodeBandBox).not.toBeNull();
    expect(legendBox!.y).toBeGreaterThanOrEqual(canvasBox!.y);
    expect(legendBox!.y + legendBox!.height).toBeLessThanOrEqual(nodeBandBox!.y + 1);
    expect(interactionBox!.y + interactionBox!.height).toBeLessThanOrEqual(nodeBandBox!.y + 1);

    await interactionBand.getByText("Layout", { exact: true }).click();
    const fitButton = interactionBand.getByRole("button", { name: /fit visible/i });
    await fitButton.click();
    await expect.poll(() => page.evaluate(() =>
      Object.keys(window.localStorage).some((key) => key.startsWith("agent-bom:graph-presentation:v1:")),
    )).toBe(true);
    await page.waitForTimeout(350);
    const savedTransform = await canvas.locator(".react-flow__viewport").getAttribute("style");
    await page.reload();
    await page.waitForLoadState("networkidle");
    await openPathQueue(page);
    await page.getByLabel("Attack path queue").getByRole("button", { name: /#1/ }).click();
    await detail.getByRole("button", { name: "Graph", exact: true }).click();
    await expect(detail.getByTestId("security-graph-investigation")).toBeVisible();
    await expect.poll(async () =>
      detail.getByTestId("security-graph-investigation").locator(".react-flow__viewport").getAttribute("style"),
    ).toBe(savedTransform);

    await page.screenshot({
      path: testInfo.outputPath(`security-graph-${viewport.width}x${viewport.height}.png`),
      fullPage: true,
    });
  });
}

test("the deploy gate is disclosure-gated rather than always expanded", async ({ page }) => {
  // "Should I deploy?" is a deliberate, occasional action — not something that
  // should cost a full band of vertical space on every visit.
  await routeCockpit(page);

  await page.goto("/security-graph?lens=attack-path");
  await page.waitForLoadState("networkidle");

  await expect(page.getByPlaceholder(/agent:claude-desktop/)).toBeHidden();
});


test("selected paths 13 and 25 retain hydrated anchors beyond fix-first enrichment", async ({ page }) => {
  await routeCockpit(page);
  const graph = buildCockpitGraph();
  const paths = Array.from({ length: 25 }, (_, index) => {
    const ordinal = index + 1;
    const source = `container:occurrence-${ordinal}`;
    const target = `finding:occurrence-${ordinal}`;
    graph.nodes.push(node(source, "container", `runtime-anchor-${ordinal}`));
    graph.nodes.push(node(target, "vulnerability", `finding-anchor-${ordinal}`, "high", 7));
    graph.edges.push(edge(source, target, "vulnerable_to"));
    return {
      ...graph.attack_paths[0]!, source, target,
      hops: [source, target], edges: ["vulnerable_to"],
      composite_risk: 10 - ordinal / 100,
      summary: `Occurrence ${ordinal} exposure`, vuln_ids: [`finding-${ordinal}`],
    };
  });
  await page.route("**/v1/graph/views/fix-first?**", route => route.fulfill({
    json: { scan_id: scanId, tenant_id: "default", created_at: createdAt, cards: [], attack_campaigns: [],
      summary: { total_paths: 25, matched_paths: 25, returned_paths: 0, highest_risk: 9.99, covered_findings: 25, node_count: graph.nodes.length, edge_count: graph.edges.length } },
  }));
  await page.route("**/v1/graph/attack-paths?**", route => {
    const offset = Number(new URL(route.request().url()).searchParams.get("offset") ?? 0);
    const selected = offset === 0 ? paths.slice(0, 12) : paths.slice(12);
    return route.fulfill({ json: {
      ...graph, attack_paths: selected,
      pagination: { total: 25, offset, limit: offset === 0 ? 12 : 100, has_more: offset === 0 },
    } });
  });
  await page.goto("/security-graph?lens=attack-path");
  await openPathQueue(page);
  const queue = page.getByLabel("Attack path queue");
  await expect(queue.getByRole("button", { name: /#10\b/ })).toBeVisible();
  await page.getByRole("button", { name: "Show 2 more", exact: true }).click();
  await page.getByRole("button", { name: "Show 10 more", exact: true }).click();
  await queue.getByRole("button", { name: /#13\b/ }).click();
  const proof = page.getByTestId("attack-path-correlation-proof");
  await proof.locator("summary").filter({ hasText: /^Exact anchors/ }).click();
  await expect(proof.getByText("runtime-anchor-13", { exact: true })).toBeVisible();
  await expect(proof.getByText("finding-anchor-13", { exact: true })).toBeVisible();
  await expect(proof.getByText(/path nodes unavailable/)).toHaveCount(0);
  await page.getByRole("button", { name: "Show 3 more", exact: true }).click();
  await queue.getByRole("button", { name: /#25\b/ }).click();
  await expect(proof.getByText("runtime-anchor-25", { exact: true })).toBeVisible();
  await expect(proof.getByText("finding-anchor-25", { exact: true })).toBeVisible();
  await expect(proof.getByText(/path nodes unavailable/)).toHaveCount(0);
});


test("URL-selected path returns to summary without reopening the path", async ({ page }) => {
  await routeCockpit(page, 200, { rollupItemCount: 30 });
  await page.goto(`/security-graph?lens=estate&scan=${scanId}&path=top`);
  await page.getByRole("button", { name: "All scopes", exact: true }).first().click();
  await expect(page.getByTestId("graph-rollup-decision-surface")).toBeVisible();
  await expect(page).not.toHaveURL(/[?&]path=/);
  await page.getByRole("button", { name: "Open scope", exact: true }).first().click();
  await page.getByRole("button", { name: "All scopes", exact: true }).first().click();
  await expect(page.getByTestId("graph-rollup-decision-surface")).toBeVisible();
  await expect(page).not.toHaveURL(/[?&]path=/);
});

for (const theme of ["light", "dark"] as const) {
  test(`large estate opens a bounded recorded neighborhood in ${theme}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await routeCockpit(page, 200, { rollupItemCount: 30 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const queries: Record<string, unknown>[] = [];
    await page.route("**/v1/graph/query", route => {
      const body = route.request().postDataJSON(); queries.push(body);
      const selected = node(body.roots[0], "account", "Selected account");
      const agent = node("agent:recorded", "agent", "Recorded agent");
      return route.fulfill({ json: { ...buildCockpitGraph(), roots: body.roots, nodes: [selected, agent],
        edges: [edge(selected.id, agent.id, "contains")], attack_paths: [], truncated: false, depth_by_node: { [selected.id]: 0, [agent.id]: 1 } } });
    });
    await page.goto("/security-graph?lens=estate");
    const scopes = page.getByTestId("graph-rollup-decision-surface");
    await expect(scopes).toBeVisible();
    await expect(page.locator(".react-flow__node")).toHaveCount(0);
    await scopes.getByRole("button", { name: "Connections", exact: true }).first().click();
    await expect(page.locator(".react-flow__node")).toHaveCount(2);
    expect(queries[0]).toMatchObject({ max_nodes: 4, max_depth: 1, scan_id: scanId });
    await page.getByRole("button", { name: "Fit all", exact: true }).click();
    await expect(page.getByRole("group", { name: "Investigation view" })).toHaveCount(0);
    await page.screenshot({ path: testInfo.outputPath(`estate-neighborhood-${theme}.png`), fullPage: false });
    await page.getByRole("button", { name: "All scopes", exact: true }).first().click();
    await expect(scopes).toBeVisible();
    await expect(page.getByTestId("graph-viewport-scope")).toBeHidden();
  });
}

for (const theme of ["light", "dark"] as const) {
  test(`nonstandard path hops expand with retry and reconciled queue counts in ${theme}`, async ({ page }, testInfo) => {
    await routeCockpit(page);
    await page.setViewportSize({ width: 1568, height: 1000 });
    await page.addInitScript((value) => localStorage.setItem("agent-bom-theme", value), theme);
    const graph = buildCockpitGraph();
    const repo = node("repo:billing", "directory", "Billing repository");
    const job = node("ci:billing", "ci_job", "Build billing");
    graph.nodes.push(repo, job);
    const extra = { ...graph.attack_paths[0]!, source: repo.id, hops: [repo.id, job.id, "pkg:form-data", "cve:form-data"] };
    await page.route("**/v1/graph/views/fix-first?**", route => route.fulfill({ json: {
      scan_id: scanId, tenant_id: "default", created_at: createdAt, attack_campaigns: [],
      summary: { total_paths: 3, matched_paths: 3, returned_paths: 1, highest_risk: 9.8, covered_findings: 1, node_count: graph.nodes.length, edge_count: graph.edges.length },
      focus: { cve: "", package: "", agent: "" },
      cards: [{ id: "priority-repo", rank: 1, title: "Billing dependency exposure", summary: "Build uses a vulnerable dependency", attack_path: extra,
        nodes: graph.nodes, sequence_labels: [], risk_reasons: [], next_actions: [],
        affected: { agents: [], servers: [], packages: [], findings: [], credentials: [], tools: [] } }],
    } }));
    await page.route("**/v1/graph/attack-paths?**", route => route.fulfill({ json: {
      ...graph, attack_paths: [extra, ...graph.attack_paths],
      pagination: { total: 3, offset: 0, limit: 100, has_more: false },
    } }));
    let attempts = 0;
    await page.route("**/v1/graph/node/*/neighbors?**", route => {
      attempts += 1;
      if (attempts === 1) return route.fulfill({ status: 503, json: { detail: "Unavailable" } });
      return route.fulfill({ json: { node_id: repo.id, scan_id: scanId, found: true, direction: "both", limit: 12,
        total_neighbors: 1, truncated: false, neighbors: [job], edges: [edge(repo.id, job.id, "contains")] } });
    });
    await page.goto("/security-graph?lens=attack-path");
    await openPathQueue(page);
    await page.getByText("Queue coverage", { exact: true }).click();
    await expect(page.getByText("3 shown · 3 loaded paths", { exact: true })).toBeVisible();
    await expect(page.getByText(/3 from the path queue/)).toBeVisible();
    await openPathQueue(page);
    await page.getByLabel("Attack path queue").getByRole("button", { name: /#1 fix first/ }).click();
    await page.getByRole("button", { name: "Connections", exact: true }).click();
    const explorer = page.getByRole("region", { name: "Expand path neighbors" });
    await explorer.getByRole("button", { name: "Expand neighbors of Billing repository" }).click();
    await explorer.getByRole("button", { name: "Retry neighbor lookup" }).click();
    await expect(explorer.getByText("Outgoing relationships", { exact: true })).toBeVisible();
    await expect(explorer.getByText("Contains", { exact: true })).toBeVisible();
    await expect(explorer.getByRole("button", { name: "Expand neighbors of Build billing" })).toBeVisible();
    await expect(explorer.getByText("leaf", { exact: true })).toHaveCount(0);
    await expect(explorer.getByRole("link", { name: "Traverse from Billing repository" })).toHaveAttribute("href", /root=repo%3Abilling/);
    await explorer.scrollIntoViewIfNeeded();
    await page.screenshot({ path: testInfo.outputPath(`path-neighbors-${theme}.png`) });
  });
}

for (const proof of [
  { theme: "light", width: 1440, height: 1000 },
  { theme: "dark", width: 1440, height: 1000 },
  { theme: "light", width: 390, height: 844 },
  { theme: "dark", width: 390, height: 844 },
] as const) {
  test(`exposure evidence pagination remains readable ${proof.theme} ${proof.width}`, async ({ page }, testInfo) => {
    await page.setViewportSize(proof);
    await page.addInitScript(theme => localStorage.setItem("agent-bom-theme", theme), proof.theme);
    await routeCockpit(page);
    const requests: URL[] = [];
    await page.route("**/v1/graph/exposure-paths?**", async route => {
      const url = new URL(route.request().url());
      requests.push(url);
      const second = url.searchParams.has("cursor");
      const source = { id: "agent:desktop", label: "A long assistant name with deployment context and an extended readable source label", role: "agent" };
      const target = { id: second ? "data:second" : "data:first", label: second ? "Second page asset" : "First page asset", role: "data" };
      const unavailable = { status: "unavailable", verdict: null };
      await route.fulfill({ contentType: "application/json", body: JSON.stringify({
        schema_version: "v1", tool: "exposure_paths", scan_id: scanId, count: 1, total: 2,
        pagination: { offset: second ? 1 : 0, limit: 25, returned: 1, has_more: !second, next_cursor: second ? null : "next-page" },
        paths: [{
          id: target.id, label: target.label, summary: "Static evidence; execution is unverified.", riskScore: 30, severity: "high",
          source, target, hops: [source, target], nodeIds: [source.id, target.id], edgeIds: ["context"], findings: [],
          relationships: [{ id: "context", source: source.id, target: target.id, relationship: "accessed", direction: "directed", traversable: false }],
          reachableTools: [], exposedCredentials: [], reachability: "unknown",
          hopEvidence: [{source_node_id: source.id, target_node_id: target.id, relationship: "accessed", source_snapshot_ids: ["synthetic-runtime:blocked"], relationship_provenance: "recorded", evidence_tier: "runtime_observed", freshness: "fresh", runtime_observed_state: "blocked", runtime_outcome: "blocked", direction: "directed", traversable: false, complete: false, truncated: false, correlation_identity_status: "current", authority: {
            status: "recorded", derivation: null, reason_codes: [], native_grants: ["SELECT", "INSERT"].map(privilege => ({
              source: "snowflake-objects", privilege, account: "synthetic-account", role: "ANALYST", object_fqn: "DB.PUBLIC.ORDERS", object_type: "table",
            })), decisions: Array.from({length: 8}, (_, index) => ({
              source: "authorization-evidence", provider: "gcp", decision: "allow", action: `storage.objects.read:${index}`,
              principal_id: source.id, resource: "projects/_/buckets/synthetic-example", binding_ids: [`source-grant:${index}`], observed_at: null,
            })),
          }}],
          evidenceDimensions: { reachability: unavailable, exploitability: unavailable, impact: unavailable, actionability: unavailable, completeness: { status: "partial" } },
          provenance: { source: "fixture", scanId },
        }],
      }) });
    });
    await page.goto(`/security-graph?lens=attack-path&scan=${scanId}`);
    await page.getByText("Investigation tools · snapshots, correlation & checks", { exact: true }).click();
    await page.getByRole("button", { name: /Exposure paths/ }).click();
    const lens = page.getByTestId("exposure-path-lens");
    await inspectPathAssessment(lens, "Unknown");
    await lens.getByText("Evidence & relationships", { exact: true }).click();
    await expect(lens.getByRole("region", { name: "Relationship proof" })).toContainText("Context only; not traversable");
    await lens.getByText("Inspect 1 hop receipt", { exact: true }).click();
    const inspector = lens.getByRole("region", { name: "Hop evidence inspector" });
    const hopButton = inspector.getByRole("button", { name: /1\. A long assistant/ });
    await hopButton.focus();
    await page.keyboard.press("Enter");
    await expect(hopButton).toHaveAttribute("aria-expanded", "true");
    await expect(inspector).toContainText("Blocked attempt");
    await expect(inspector).toContainText("synthetic-runtime:blocked");
    await expect(inspector).toContainText("This receipt cannot establish a successful downstream action");
    const authority = inspector.getByRole("region", { name: "Recorded authority" });
    await expect(authority).toContainText("Snapshot evidence, not a current permission check");
    await expect(authority.getByText("storage.objects.read:0 · allow", {exact: true})).toBeVisible();
    await authority.getByRole("button", {name: "Next receipts"}).click();
    await expect(authority.getByText("storage.objects.read:4 · allow", {exact: true})).toBeVisible();
    const bindings = authority.getByText("Source bindings (1)", {exact: true}).first();
    await bindings.click();
    await expect(authority.getByText("source-grant:4", {exact: true})).toBeVisible();
    await authority.getByRole("button", {name: "Next receipts"}).click();
    await expect(authority.getByText("SELECT · Native grant", {exact: true})).toBeVisible();
    await authority.getByText("INSERT · Native grant", {exact: true}).scrollIntoViewIfNeeded();
    await expect(authority.getByText("INSERT · Native grant", {exact: true})).toBeVisible();
    await expect(authority).toContainText("Session authorization and policy effects require separate evidence");
    await authority.getByRole("list", {name: "Authority receipts"}).evaluate(element => { element.scrollTop = 0; });
    expect(await authority.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
    await authority.evaluate(element => element.scrollIntoView({block: "start"}));
    await authority.screenshot({path: testInfo.outputPath(`hop-authority-${proof.theme}-${proof.width}.png`)});
    await hopButton.focus();
    expect(await inspector.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
    await inspector.screenshot({path: testInfo.outputPath(`hop-evidence-${proof.theme}-${proof.width}.png`)});
    await page.keyboard.press("Enter");
    await expect(hopButton).toHaveAttribute("aria-expanded", "false");
    await lens.getByRole("button", { name: "Next paths" }).click();
    await expect(lens.getByRole("status")).toContainText("Page 2");
    await expect(lens.getByRole("button", { name: "Next paths" })).toBeDisabled();
    await expect(lens.getByRole("list", { name: "Exposure path queue" })).toContainText(/Second Page Asset/i);
    await lens.getByRole("button", { name: "Previous paths" }).click();
    await expect(lens.getByRole("status")).toContainText("Page 1");
    // The initial request can resolve latest before the parent loads its scope;
    // both continuation and backward navigation must retain the resolved scan.
    expect(requests.slice(-2).every(url => url.searchParams.get("scan_id") === scanId)).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  });
}

for (const theme of ["light", "dark"] as const) {
  test(`focused path and qualifications fit the first desktop viewport ${theme}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await routeCockpit(page, undefined, { qualifiedEvidence: true });
    await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&node=pkg%3Aform-data&cve=CVE-2025-7783&package=form-data`);
    const detail = page.getByTestId("selected-exposure-path");
    await expect(detail).toBeVisible();
    const diagram = detail.getByRole("region", { name: "Interactive graph", exact: true });
    await expect(diagram).toBeVisible();
    // Resolving the parent scan scope can briefly remount this diagram. Read
    // one box per attempt and retry missing geometry without accepting it.
    await expect.poll(async () => {
      const bounds = await diagram.boundingBox();
      return bounds ? bounds.y + bounds.height : Number.POSITIVE_INFINITY;
    }).toBeLessThanOrEqual(900);
    await inspectPathAssessment(detail, "Reachability");
    await inspectPathAssessment(detail, "Exploitability");
    await inspectPathAssessment(detail, "Assessment completeness");
    await expect(detail.getByTestId("exposure-path-primary-action")).toBeVisible();
    await expect(detail.getByText("Evidence & relationships", { exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath(`focused-path-${theme}.png`) });
  });
}

for (const theme of ["light", "dark"] as const) {
  for (const width of [1568, 390]) {
    test(`investigation workspace keeps graph primary with usable pane navigation ${theme} ${width}`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 1000 });
      await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
      await routeCockpit(page, undefined, { qualifiedEvidence: true });
      await page.goto(`/security-graph?lens=attack-path&scan=${scanId}`);
      const workspace = page.getByRole("region", { name: "Investigation workspace" });
      const detail = workspace.getByRole("region", { name: "Selected path detail" });
      await expect(detail).toBeVisible();
      await inspectPathAssessment(detail, /unknown/i);
      await expect(detail.getByRole("heading", { level: 2 })).not.toContainText(/reachable|exploitable/i);
      const queue = page.getByLabel("Attack path queue");
      await expect(queue).not.toContainText(/Critical package reachable/);
      if (width < 1024) {
        await expect(queue).toBeHidden();
        await page.getByRole("button", { name: /Paths & filters/ }).click();
        await expect(queue).toBeVisible();
        await expect(detail).toBeHidden();
        await queue.getByRole("button", { name: /#2/ }).click();
        await expect(queue).toBeHidden();
        await expect(detail).toBeVisible();
        await expect(detail.getByRole("heading", { level: 2 })).toContainText("GITHUB PERSONAL ACCESS TOKEN");
        const graph = detail.getByTestId("security-graph-investigation");
        await expect(graph.locator(".react-flow__node")).toHaveCount(3);
        await expect(graph.getByRole("button", { name: "Next graph node" })).toHaveCount(0);
      } else {
        await openPathQueue(page);
        const [queueBox, detailBox] = await Promise.all([queue.boundingBox(), detail.boundingBox()]);
        expect(queueBox!.x + queueBox!.width).toBeLessThan(detailBox!.x);
        expect(queueBox!.height).toBeLessThanOrEqual(650);
        const graph = detail.getByRole("region", { name: "Interactive graph", exact: true });
        const proof = detail.getByRole("complementary", { name: "Selected path evidence" });
        const [graphBox, proofBox] = await Promise.all([graph.boundingBox(), proof.boundingBox()]);
        expect(proofBox!.y).toBeGreaterThanOrEqual(graphBox!.y + graphBox!.height);
        expect(proofBox!.width).toBeGreaterThan(0);
        expect(graphBox!.y + graphBox!.height).toBeLessThan(1000);
      }
      await expect(page.getByRole("button", { name: "Should I deploy?" })).toBeHidden();
      await page.getByText("Investigation tools · snapshots, correlation & checks", { exact: true }).click();
      await page.getByRole("button", { name: "Should I deploy?" }).click();
      await expect(page.getByPlaceholder(/agent:claude-desktop/)).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
      await page.getByText("Investigation tools · snapshots, correlation & checks", { exact: true }).click();
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({ path: testInfo.outputPath(`workspace-${theme}-${width}.png`), fullPage: true });
    });
  }
}

for (const theme of ["light", "dark"] as const) {
 for (const height of [800, 1000]) {
  test(`selected Graph keeps its nodes in the first desktop viewport ${theme} ${height}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 1568, height });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await routeCockpit(page, undefined, { qualifiedEvidence: true });
    await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&node=pkg%3Aform-data&cve=CVE-2025-7783&package=form-data`);
    const detail = page.getByTestId("selected-exposure-path");
    await detail.getByRole("button", { name: "Graph", exact: true }).click();
    const canvas = page.getByTestId("security-graph-investigation");
    await expect(canvas.locator(".react-flow__node")).toHaveCount(4);
    await expect(canvas.locator(".react-flow__edge")).toHaveCount(3);
    let previousTransform = "";
    let unchangedSince = Date.now();
    await expect.poll(async () => {
      const transform = await canvas.locator(".react-flow__viewport").getAttribute("style");
      if (transform !== previousTransform) {
        previousTransform = transform ?? "";
        unchangedSince = Date.now();
      }
      return Date.now() - unchangedSince >= 350;
    }, { intervals: [100] }).toBe(true);
    await expect.poll(() => canvas.locator(".react-flow__node").evaluateAll(elements =>
      elements.every(element => {
        const box = element.getBoundingClientRect();
        const flow = element.closest(".react-flow")!;
        const frame = flow.getBoundingClientRect();
        const controls = flow.querySelector(".react-flow__controls")!.getBoundingClientRect();
        const overlapsControls = box.left < controls.right && box.right > controls.left && box.top < controls.bottom && box.bottom > controls.top;
        return box.top >= 0 && box.bottom <= innerHeight && box.left >= frame.left && box.right <= frame.right && !overlapsControls;
      }),
    )).toBe(true);
    await inspectPathAssessment(detail, /unknown/i);
    await expect(detail.getByRole("complementary", { name: "Selected path evidence" })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath(`selected-graph-${theme}-${height}.png`), fullPage: true });
  });
}
}

for (const theme of ["light", "dark"] as const) {
 for (const width of [390, 1568]) {
  test(`node impact qualifies bounded upstream connections in ${theme} at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await routeCockpit(page, undefined, { qualifiedEvidence: true });
    const graph = buildCockpitGraph();
    const selectedNode = graph.nodes.find(item => item.id === "pkg:form-data")!;
    await page.route("**/v1/graph/node/*?**", route => route.fulfill({ json: {
      node: selectedNode, edges_in: [], edges_out: [], neighbors: [], sources: ["scan"],
      impact: { node_id: selectedNode.id, affected_nodes: ["agent:desktop", "server:github"], affected_count: 2,
        affected_by_type: { agent: 1, server: 1 }, max_depth_reached: 2,
        completeness: { status: "truncated", complete: false, truncated: true, sampled: false, returned: 2, reason: "depth_limit" } },
    } }));
    await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&node=pkg%3Aform-data&cve=CVE-2025-7783&package=form-data`);
    await page.getByTestId("selected-exposure-path").getByRole("button", { name: "Graph", exact: true }).click();
    await page.locator('.react-flow__node[data-id="pkg:form-data"]').click();
    const pinned = page.getByText("Pinned form-data@4.0.0", { exact: true });
    await expect(pinned).toBeVisible();
    await pinned.scrollIntoViewIfNeeded();
    await page.screenshot({ path: testInfo.outputPath(`pinned-name-${theme}-${width}.png`) });
    const drawer = page.getByTestId("graph-entity-drawer");
    await drawer.getByTestId("graph-drawer-tab-impact").click();
    const panel = drawer.getByTestId("graph-drawer-panel-impact");
    await expect(panel).toContainText("Upstream connected entities");
    await expect(panel).toContainText("Partial traversal · 2 entities returned");
    await expect(panel).toContainText("additional upstream connections may exist");
    await expect(panel).toContainText("do not establish exploitability, successful actions or observed damage");
    await expect(panel).toContainText("Agent: 1");
    await expect(panel).toContainText("Server: 1");
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await panel.screenshot({ path: testInfo.outputPath(`impact-scope-${theme}-${width}.png`) });
  });
 }
}

for (const theme of ["light", "dark"] as const) {
  test(`mobile selected Graph shows a short path whole in one column ${theme}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await routeCockpit(page, undefined, { qualifiedEvidence: true });
    await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&node=pkg%3Aform-data&cve=CVE-2025-7783&package=form-data`);
    const detail = page.getByTestId("selected-exposure-path");
    await detail.getByRole("button", { name: "Graph", exact: true }).click();
    const canvas = page.getByTestId("security-graph-investigation");
    await expect(canvas.locator(".react-flow__node")).toHaveCount(4);
    await expect(canvas.locator(".graph-relationship-label")).toHaveCount(3);
    await expect(canvas.getByRole("button", { name: "Next graph node" })).toHaveCount(0);
    await expect(canvas.getByText(/Focused view/)).toHaveCount(0);
    const band = canvas.getByTestId("security-graph-interaction-band");
    await expect(band.getByRole("group", { name: "Exposure path view" })).toBeVisible();
    expect((await band.boundingBox())!.height).toBeLessThan(70);
    // Every hop, name and relationship chip sits inside the canvas, top to bottom in path order.
    await expect.poll(() => canvas.evaluate(element => {
      const frame = element.querySelector(".react-flow")!.getBoundingClientRect();
      const inside = (box: DOMRect) => box.width === 0 || box.left >= frame.left - 0.5 && box.right <= frame.right + 0.5
        && box.top >= frame.top - 0.5 && box.bottom <= frame.bottom + 0.5;
      const parts = [...element.querySelectorAll(".graph-relationship-label, [data-graph-entity] > *")];
      const glyphs = ["agent:desktop", "server:github", "pkg:form-data", "cve:form-data"].map(id =>
        element.querySelector(`.react-flow__node[data-id="${id}"] .graph-entity-glyph`)!.getBoundingClientRect());
      const ordered = glyphs.every((box, index) => index === 0 || box.top > glyphs[index - 1]!.bottom);
      const aligned = glyphs.every(box => Math.abs(box.left + box.width / 2 - (glyphs[0]!.left + glyphs[0]!.width / 2)) < 4);
      return parts.every(part => inside(part.getBoundingClientRect())) && ordered && aligned;
    })).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await canvas.screenshot({ path: testInfo.outputPath(`mobile-column-path-${theme}.png`) });
  });

  test(`mobile selected Graph navigates a long path at readable zoom in ${theme}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme === "light" ? "dark" : "light");
    await routeCockpit(page, undefined, { qualifiedEvidence: true, longPathNodeCount: 10 });
    await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&node=pkg%3Aform-data&cve=CVE-2025-7783&package=form-data`);
    await page.getByRole("button", { name: `Switch to ${theme} theme`, exact: true }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    const detail = page.getByTestId("selected-exposure-path");
    // The unified interactive graph owns both path rendering and navigation.
    await detail.getByRole("button", { name: "Graph", exact: true }).click();
    const canvas = page.getByTestId("security-graph-investigation");
    await expect(canvas.locator(".react-flow__node")).toHaveCount(10);
    await expect.poll(() => canvas.locator('.react-flow__node[data-id="agent:desktop"]').evaluate(element => {
      const width = element.getBoundingClientRect().width;
      const label = element.querySelector("p")!;
      const zoom = new DOMMatrixReadOnly(getComputedStyle(element.closest(".react-flow")!.querySelector(".react-flow__viewport")!).transform).a;
      return width >= 180 && parseFloat(getComputedStyle(label).fontSize) * zoom >= 12 && element.getBoundingClientRect().top >= 0 && element.getBoundingClientRect().bottom <= innerHeight;
    })).toBe(true);
    await expect(canvas.getByText("Focused view · 1 of 10")).toBeVisible();
    await expect.poll(() => canvas.evaluate(element => element.getBoundingClientRect().top)).toBeLessThan(250);
    await page.screenshot({ path: testInfo.outputPath(`mobile-readable-initial-${theme}.png`), fullPage: false });
    await expect(canvas.getByRole("button", { name: "Previous graph node" })).toBeDisabled();
    for (let step = 2; step <= 10; step++) {
      await canvas.getByRole("button", { name: "Next graph node" }).click();
      await expect(canvas.getByText(`Focused view · ${step} of 10`)).toBeVisible();
      const expectedId = step === 10 ? "cve:form-data" : step === 9 ? "pkg:form-data" : `server:hop-${step - 2}`;
      await expect.poll(() => canvas.locator(`.react-flow__node[data-id="${expectedId}"]`).evaluate(element => {
        const box = element.getBoundingClientRect();
        return box.width >= 180 && box.left >= 0 && box.right <= innerWidth && box.top >= 0 && box.bottom <= innerHeight;
      })).toBe(true);
    }
    await expect(canvas.getByRole("button", { name: "Next graph node" })).toBeDisabled();
    const last = canvas.locator('.react-flow__node[data-id="cve:form-data"]');
    await expect.poll(() => last.evaluate(element => {
      const box = element.getBoundingClientRect();
      const frame = element.closest(".react-flow")!.getBoundingClientRect();
      return box.width >= 180 && box.left >= frame.left && box.right <= frame.right && box.top >= frame.top && box.bottom <= frame.bottom;
    })).toBe(true);
    await canvas.getByLabel("Graph options", { exact: true }).click();
    await canvas.getByRole("button", { name: "Fit visible graph", exact: true }).click();
    await expect(canvas.getByText("Overview · 10 nodes")).toBeVisible();
    await canvas.getByLabel("Graph options", { exact: true }).click();
    await canvas.getByRole("button", { name: "Previous graph node" }).click();
    await expect(canvas.getByText("Focused view · 9 of 10")).toBeVisible();
    await expect.poll(() => canvas.locator('.react-flow__node[data-id="pkg:form-data"]').evaluate(element => {
      const box = element.getBoundingClientRect();
      const frame = element.closest(".react-flow")!.getBoundingClientRect();
      return box.width >= 180 && box.left >= frame.left && box.right <= frame.right;
    })).toBe(true);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await canvas.screenshot({ path: testInfo.outputPath(`mobile-readable-graph-${theme}.png`) });
  });
}

for (const proof of [{ theme: "light", width: 1440 }, { theme: "dark", width: 1440 }, { theme: "dark", width: 390 }]) {
  test(`agent investigation questions retain honest scope ${proof.theme} ${proof.width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: proof.width, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), proof.theme);
    await routeCockpit(page, undefined, { qualifiedEvidence: true });
    await page.route("**/v1/runtime/trace-explorer?**", route => route.fulfill({ json: { sessions: [], session_count: 0, blocked_count: 0 } }));
    await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&agent=claude-desktop`);
    const questions = page.getByRole("region", { name: "Agent investigation questions", exact: true });
    await expect(questions).toBeVisible();
    await questions.getByText("Investigate this path", { exact: true }).click();
    await questions.getByRole("button", { name: "CVE conditions" }).click();
    await expect(questions).toContainText("Local exploitability: not assessed");
    await expect(questions.getByText("Not recorded", { exact: true })).toHaveCount(4);
    await questions.scrollIntoViewIfNeeded();
    await page.screenshot({ path: testInfo.outputPath(`agent-investigation-${proof.theme}-${proof.width}.png`) });
    await questions.getByRole("button", { name: "Assume compromise" }).click();
    await questions.getByRole("checkbox").check();
    await expect(questions).toContainText("Scenario assumption only");
    await questions.getByRole("button", { name: "Potential impact" }).click();
    await expect(questions).toContainText("No downstream data asset");
    await questions.getByRole("button", { name: "Recorded activity" }).click();
    await questions.getByRole("link", { name: "Recorded activity for claude-desktop" }).click();
    await expect(page).toHaveURL(new RegExp(`agent=claude-desktop&scan=${scanId}`));
    await expect(page.getByText(/No activity matched this agent/)).toBeVisible();
    await expect(page.getByText(/not.*scan|scan.*not/i).first()).toBeVisible();
  });
}

for (const theme of ["light", "dark"] as const) {
  for (const width of [390, 1440]) {
    test(`environment scope filters and evidence remain readable ${theme} ${width}`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 900 });
      await page.addInitScript((value) => localStorage.setItem("agent-bom-theme", value), theme);
      await routeCockpit(page, 200, { rollupItemCount: 30 });
      await page.goto(`/graph?scan=${scanId}&rollup=1`);
      const surface = page.getByTestId("graph-rollup-decision-surface");
      await expect(surface).toBeVisible();
      await surface.getByText("Filter nodes and scopes", { exact: true }).click();
      await surface.getByRole("button", { name: "All 30", exact: true }).click();
      await surface.getByLabel("Search this scope").fill("production");
      await expect(surface.locator("article")).toHaveCount(1);
      await surface.getByText("Details · 1 relationship row", { exact: true }).click();
      await expect(surface.getByText(/do not establish runtime execution/)).toBeVisible();
      expect(await surface.evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
      await page.screenshot({ path: testInfo.outputPath(`environment-focus-${theme}-${width}.png`), fullPage: true });
    });
  }
}

test("environment scope filtering stays bounded with 3000 returned scopes", async ({ page }, testInfo) => {
  await routeCockpit(page, 3000, { rollupItemCount: 3000 });
  await page.goto(`/graph?scan=${scanId}&rollup=1`);
  const surface = page.getByTestId("graph-rollup-decision-surface");
  await expect(surface).toBeVisible();
  await surface.getByRole("button", { name: "All 3000", exact: true }).click();
  await expect(surface.locator("article")).toHaveCount(12);
  await surface.getByText("Filter nodes and scopes", { exact: true }).click();
  const durations: number[] = [];
  for (let index = 0; index < 10; index += 1) {
    const start = performance.now();
    await surface.getByLabel("Search this scope").fill(index % 2 ? "production" : "development");
    await expect(surface.locator("article")).toHaveCount(1);
    durations.push(performance.now() - start);
  }
  console.info("Scope filter fixture max milliseconds:", Math.max(...durations).toFixed(1));
  await testInfo.attach("filter-timing-fixture", { body: JSON.stringify({ scopes: 3000, samples_ms: durations, max_ms: Math.max(...durations), note: "Local browser automation with mocked API; excludes production backend latency." }), contentType: "application/json" });
});

for (const theme of ["light", "dark"] as const) {
  for (const width of [390, 1440]) {
    test(`finding returns from linked asset with original scope ${theme} ${width}`, async ({ page }, testInfo) => {
      await page.addInitScript((value) => localStorage.setItem("agent-bom-theme", value), theme);
      await page.setViewportSize({ width, height: 1000 });
      await routeCockpit(page, undefined, { emptyFocusResults: true });
      await page.route("**/v1/posture", (route) => route.fulfill({ status: 503, json: { detail: "No posture fixture" } }));
      await page.route("**/v1/graph/correlations?**", (route) => route.fulfill({ json: { items: [], count: 0 } }));
      const linkedGraph = buildCockpitGraph();
      await page.route("**/v1/graph/query", (route) => route.fulfill({ json: { ...linkedGraph, root_id: "pkg:form-data", truncated: false } }));
      await page.route("**/v1/graph/node/*?**", (route) => route.fulfill({ json: {
        node: linkedGraph.nodes.find((node) => node.id === "pkg:form-data"),
        edges_in: [], edges_out: [], neighbors: [], sources: [], impact: { upstream_agents: [], affected_count: 0 },
      } }));
      const finding = "occurrence/one&exact";
      const params = new URLSearchParams({ lens: "attack-path", scan: scanId, finding_scan: scanId, finding, node: "pkg:form-data" });
      await page.goto(`/security-graph?${params}`);
      await expect(page.getByRole("complementary", { name: "Finding investigation context" })).toBeVisible();
      await page.getByRole("link", { name: "Inspect linked asset" }).click();
      await expect.poll(() => new URL(page.url()).searchParams.get("lens")).toBe("lineage");
      await expect(page.getByRole("link", { name: "Return to finding" })).toBeVisible();
      const context = page.getByRole("complementary", { name: "Finding investigation context" });
      await expect(context).toContainText(scanId);
      expect(await context.evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
      if (width === 390) await page.getByTestId("graph-entity-drawer").getByRole("button", { name: "Close", exact: true }).last().click();
      await page.screenshot({ path: testInfo.outputPath(`finding-return-${theme}-${width}.png`), fullPage: true });
      const reads: URL[] = [];
      await page.route("**/v1/findings**", (route) => {
        const url = new URL(route.request().url());
        if (url.pathname === "/v1/findings") reads.push(url);
        return route.fulfill({ json: { findings: [], triage: [], count: 0, total: 0, has_more: false, warnings: [] } });
      });
      await page.getByRole("link", { name: "Return to finding" }).click();
      await expect.poll(() => new URL(page.url()).pathname).toBe("/findings");
      await expect.poll(() => reads.length).toBeGreaterThan(0);
      expect(reads[0]!.searchParams.get("scan_id")).toBe(scanId);
      expect(reads[0]!.searchParams.get("q")).toBe(finding);
      expect(reads[0]!.searchParams.get("window_days")).toBe("0");
      await page.goBack();
      await expect(page.getByRole("link", { name: "Return to finding" })).toBeVisible();
      expect(new URL(page.url()).searchParams.get("finding_scan")).toBe(scanId);
    });
  }
}


for (const theme of ["light", "dark"] as const) {
  for (const width of [1440, 390]) {
    for (const mode of ["filter", "finding"] as const) {
    test(`filtered queue reaches later-page evidence ${mode} ${theme} ${width}`, async ({ page }, testInfo) => {
      await routeCockpit(page);
      await page.route("**/v1/graph/presets", route => route.fulfill({ json: [] }));
      await page.setViewportSize({ width, height: 900 });
      await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
      const graph = buildCockpitGraph();
      const paths = Array.from({ length: 26 }, (_, index) => {
        const source = `agent:paged-${index}`;
        const target = `finding:paged-${index}`;
        const agent = node(source, "agent", `Page agent ${index}`);
        agent.attributes = { evidence_tier: index === 25 ? "static_scan" : "runtime_observed" };
        graph.nodes.push(agent, node(target, "vulnerability", `Page finding ${index}`, "high", 7));
        graph.edges.push(edge(source, target, "vulnerable_to"));
        return { ...graph.attack_paths[0]!, source, target, hops: [source, target], edges: ["vulnerable_to"],
          composite_risk: 8, summary: `Page occurrence ${index}`, vuln_ids: [`page-finding-${index}`] };
      });
      await page.route("**/v1/graph/views/fix-first?**", route => route.fulfill({ json: {
        scan_id: scanId, tenant_id: "default", created_at: createdAt, cards: [], attack_campaigns: [],
        summary: { total_paths: 26, matched_paths: 26, returned_paths: 0, highest_risk: 8, covered_findings: 26, node_count: graph.nodes.length, edge_count: graph.edges.length },
      } }));
      const offsets: number[] = [];
      let failNext = theme === "dark" && width === 1440;
      await page.route("**/v1/graph/attack-paths?**", route => {
        const offset = Number(new URL(route.request().url()).searchParams.get("offset") ?? 0);
        offsets.push(offset);
        if (offset === 25 && failNext) { failNext = false; return route.fulfill({ status: 503, json: { detail: "Temporarily unavailable" } }); }
        const selected = paths.slice(offset, offset + 25);
        const ids = new Set(selected.flatMap(path => path.hops));
        return route.fulfill({ json: { ...graph, attack_paths: selected,
          nodes: graph.nodes.filter(item => ids.has(item.id)), edges: graph.edges.filter(item => ids.has(item.source) && ids.has(item.target)),
          pagination: { total: 26, offset, limit: 25, has_more: offset === 0 },
          completeness: { returned: selected.length, total: 26, truncated: offset === 0 },
        } });
      });
      await page.goto(`/security-graph?lens=attack-path&scan=${scanId}${mode === "finding" ? "&cve=page-finding-25" : ""}`);
      if (mode === "filter") {
        await openPathQueue(page);
        await page.getByText("Filters & presets", { exact: true }).click();
        await page.getByRole("button", { name: "Static", exact: true }).click();
      }
      await expect(page.getByRole("heading", { name: "No matching paths in loaded pages" })).toBeVisible();
      await page.screenshot({ path: testInfo.outputPath(`filtered-path-empty-${mode}-${theme}-${width}.png`), fullPage: true });
      await page.getByRole("button", { name: "Load next 25 paths", exact: true }).click();
      if (theme === "dark" && width === 1440) {
        await expect(page.getByRole("alert").filter({ hasText: "Loaded evidence is retained" })).toBeVisible();
        await page.getByRole("button", { name: "Load next 25 paths", exact: true }).click();
      }
      await openPathQueue(page);
      await expect(page.getByLabel("Attack path queue")).toContainText(/Page agent 25/i);
      expect(offsets).toEqual(theme === "dark" && width === 1440 ? [0, 25, 25] : [0, 25]);
      await expect(page.getByRole("button", { name: "Load next 25 paths", exact: true })).toHaveCount(0);
      await openPathQueue(page);
      await page.getByLabel("Attack path queue").getByRole("button", { name: /Page agent 25/i }).click();
      await expect(page.getByTestId("selected-exposure-path")).toContainText(/Page agent 25/i);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      await page.screenshot({ path: testInfo.outputPath(`filtered-path-queue-${mode}-${theme}-${width}.png`), fullPage: true });
    });
  }
}
}

for (const estateSize of [10, 1_000, 10_000]) {
  for (const theme of ["light", "dark"] as const) {
    for (const width of [390, 1440]) {
      test(`bounded investigation ${estateSize} nodes ${theme} ${width}`, async ({ page }, testInfo) => {
        await page.setViewportSize({ width, height: 1000 });
        await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
        await routeCockpit(page, estateSize);
        const graph = buildCockpitGraph(estateSize);
        const requests: number[] = [];
        await page.route("**/v1/graph/attack-paths?**", route => {
          const limit = Number(new URL(route.request().url()).searchParams.get("limit"));
          requests.push(limit);
          return route.fulfill({ json: {
            ...graph, nodes: graph.nodes.slice(0, 100),
            pagination: { total: 2, offset: 0, limit, has_more: false },
            completeness: { returned: 2, total: 2, truncated: false, reason: "" },
          } });
        });
        await page.route("**/v1/graph/views/fix-first?**", route => route.fulfill({ json: {
          scan_id: scanId, tenant_id: "default", created_at: createdAt, cards: [], attack_campaigns: [],
          summary: { total_paths: 2, matched_paths: 2, returned_paths: 0, highest_risk: 9.8, covered_findings: 1, node_count: estateSize, edge_count: graph.edges.length },
        } }));
        await page.route("**/v1/intel/sources", route => route.fulfill({ json: { sources: [] } }));
        const errors: string[] = [];
        page.on("pageerror", error => errors.push(error.message));
        await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&path_view=graph`);
        await expect(page.getByRole("heading", { name: "Investigation", exact: true })).toBeVisible();
        await expect.poll(() => page.locator(".react-flow__node").count()).toBeGreaterThan(0);
        expect(await page.locator(".react-flow__node").count()).toBeLessThanOrEqual(100);
        expect(requests.length).toBeGreaterThan(0);
        expect(requests.every(limit => limit === 10)).toBe(true);
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
        expect(errors).toEqual([]);
        await page.screenshot({ path: testInfo.outputPath(`bounded-${estateSize}-${theme}-${width}.png`), fullPage: true });
      });
    }
  }
}

for (const theme of ["dark", "light"] as const) {
  for (const width of [1440, 390]) {
    test(`focused first view and keyboard queue ${theme} ${width}`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 900 });
      await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
      await routeCockpit(page);
      await page.goto(`/security-graph?lens=attack-path&scan=${scanId}`);
      const workspace = page.getByRole("region", { name: "Investigation workspace" });
      await expect(workspace).toHaveAttribute("data-layout", "focused-path");
      await expect(page.getByTestId("selected-exposure-path")).toBeVisible();
      await expect(page.getByTestId("exposure-path-primary-action")).toHaveCount(1);
      expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false);
      await page.screenshot({ path: testInfo.outputPath(`focused-first-${theme}-${width}.png`), fullPage: true });
      await openPathQueue(page);
      const first = page.getByLabel("Attack path queue").getByRole("button").first();
      await first.focus();
      await page.keyboard.press("ArrowRight");
      await expect(page.getByRole("status")).toContainText("Focused path 2");
      expect(new URL(page.url()).searchParams.get("scan")).toBe(scanId);
    });
  }
  for (const status of [403, 503]) {
    test(`investigation denied or unavailable ${theme} ${status}`, async ({ page }, testInfo) => {
      await routeCockpit(page);
      await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
      await page.route("**/v1/graph/attack-paths?**", route => route.fulfill({ status, json: { detail: "Unavailable" } }));
      await page.goto(`/security-graph?lens=attack-path&scan=${scanId}`);
      await expect(page.getByText("Cannot load attack paths for this snapshot")).toBeVisible();
      await expect(page.getByTestId("exposure-path-primary-action")).toHaveCount(0);
      await page.screenshot({ path: testInfo.outputPath(`unavailable-${theme}-${status}.png`), fullPage: true });
    });
  }
}

for (const theme of ["light", "dark"] as const) {
  test(`impact step reads scoped reverse reachability in ${theme}`, async ({ page }, testInfo) => {
    await routeCockpit(page);
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await page.route("**/v1/graph/impact?**", route => route.fulfill({ json: {
      scan_id: scanId, tenant_id: "default", snapshot_generation: "a".repeat(32), node_id: "cve:form-data",
      affected_nodes: ["agent:desktop", "server:github", "pkg:form-data"], affected_count: 3,
      affected_by_type: { agent: 1, server: 1, package: 1 }, max_depth_reached: 3,
      completeness: { complete: true },
    } }));
    await page.goto(`/security-graph?scan=${scanId}&lens=attack-path`);
    await page.getByTestId("investigation-step-strip").getByRole("button", { name: /Impact/ }).click();
    await expect(page.getByRole("region", { name: "Path impact" })).toContainText("3 upstream related nodes");
    await expect(page.getByRole("link", { name: "Explore upstream relationships" })).toHaveAttribute("href", /direction=reverse/);
    await page.screenshot({ path: testInfo.outputPath(`path-impact-${theme}.png`), fullPage: true });
  });

  test(`scope selection preserves the parent until explicit drill-down in ${theme}`, async ({ page }, testInfo) => {
    await routeCockpit(page);
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const drilled: string[] = [];
    page.on("request", request => { const url = new URL(request.url()); if (url.pathname === "/v1/graph/rollup" && url.searchParams.has("node")) drilled.push(url.searchParams.get("node")!); });
    await page.goto(`/graph?scan=${scanId}&rollup=1`);
    const productionScope = page.locator('.react-flow__node[data-id="account:production"]');
    await expect(productionScope).toContainText("900");
    await expect(productionScope).toContainText("Critical · highest severity");
    await expect(page.locator(".graph-aggregate-label")).toHaveText("35 relationships");
    await page.waitForLoadState("networkidle");
    await page.screenshot({ path: testInfo.outputPath(`scope-overview-${theme}.png`), fullPage: true });
    await productionScope.click();
    await expect(page.getByTestId("graph-entity-drawer")).toBeVisible();
    await expect(page.getByRole("complementary", { name: "Scope details" })).toContainText("Severity of contained entities");
    await expect(page.getByRole("button", { name: "Show blast radius" })).toHaveCount(0);
    expect(drilled).toEqual([]);
    await expect(page.locator('.react-flow__node[data-id="account:production"]')).toBeVisible();
    await expect.poll(async () => {
      const canvas = await page.locator(".react-flow").boundingBox();
      const neighbor = await page.locator('.react-flow__node[data-id="account:development"]').boundingBox();
      return !!canvas && !!neighbor && neighbor.x >= canvas.x && neighbor.x + neighbor.width <= canvas.x + canvas.width + 1;
    }).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`scope-selected-${theme}.png`), fullPage: true });
    await page.getByRole("button", { name: "Explore scope", exact: true }).click();
    await expect.poll(() => drilled).toContain("account:production");
  });
}

test("incoming traversal survives URL synchronization and reload", async ({ page }) => {
  await routeCockpit(page);
  const directions: string[] = [];
  await page.route("**/v1/graph/query", route => {
    const body = route.request().postDataJSON(); directions.push(body.direction);
    const graph = buildCockpitGraph();
    return route.fulfill({ json: { ...graph, roots: body.roots, direction: body.direction, truncated: false, missing_roots: [], depth_by_node: { "server:github": 0, "agent:desktop": 1 } } });
  });
  await page.goto(`/security-graph?scan=${scanId}&investigate=1&root=server%3Agithub&direction=reverse&lens=lineage`);
  await openEvidenceControls(page);
  await expect(page.getByRole("combobox", { name: "Traversal direction" })).toHaveValue("reverse");
  await expect(page).toHaveURL(/direction=reverse/);
  expect(directions[0]).toBe("reverse");
  await page.reload();
  await openEvidenceControls(page);
  await expect(page.getByRole("combobox", { name: "Traversal direction" })).toHaveValue("reverse");
  expect(directions.every(value => value === "reverse")).toBe(true);
});

test("aggregate edge opens recorded counts without inventing direct evidence", async ({ page }, testInfo) => {
  await routeCockpit(page);
  await page.goto(`/graph?scan=${scanId}&rollup=1`);
  await page.waitForLoadState("networkidle");
  const edge = page.locator(".react-flow__edge").first();
  await expect(edge).toBeAttached();
  const point = await edge.locator(".react-flow__edge-interaction").evaluate(element => {
    const path = element as SVGPathElement;
    const local = path.getPointAtLength(path.getTotalLength() / 2);
    const screen = new DOMPoint(local.x, local.y).matrixTransform(path.getScreenCTM()!);
    return { x: screen.x, y: screen.y };
  });
  await page.mouse.click(point.x, point.y);
  const detail = page.getByRole("dialog", { name: "Scope relationship details" });
  await expect(detail).toContainText("35 recorded relationships");
  await expect(detail).toContainText("Not recorded");
  await expect(detail).toContainText("Count unavailable");
  await page.screenshot({ path: testInfo.outputPath("aggregate-relationship-detail.png"), fullPage: true });
});

test("long digest labels stay inside their graph nodes", async ({ page }) => {
  await routeCockpit(page, undefined, { longNodeLabel: true });
  await page.goto(`/graph?scan=${scanId}&rollup=0`);
  const node = page.locator('.react-flow__node[data-id="server:github"]');
  await expect(node).toBeVisible();
  const label = node.locator('[data-graph-entity="true"] > p').first();
  await expect(label).toBeVisible();
  await expect.poll(() => node.evaluate(element => {
    const bounds = element.getBoundingClientRect();
    const caption = element.querySelector('[data-graph-entity="true"] > p')!.getBoundingClientRect();
    return caption.left >= bounds.left - 1 && caption.right <= bounds.right + 1;
  })).toBe(true);
});

for (const width of [1440, 1920]) for (const theme of ["light", "dark"]) {
  test(`reference correlation captions stay separate ${theme} ${width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: width === 1440 ? 900 : 1080 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await routeCockpit(page, undefined, { referenceGraph: true });
    await page.goto(`/graph?scan=${scanId}&rollup=0&capture=1&layers=server,agent,container,package,vulnerability,tool,serviceAccount,dataStore,sourceFile`);
    await expect(page.locator(".react-flow__node")).toHaveCount(10);
    await page.locator(".react-flow__controls-fitview").click();
    await page.waitForLoadState("networkidle");
    await page.screenshot({ path: testInfo.outputPath("reference-captions.png"), fullPage: true });
    const collisions = await visibleGraphLabelCollisions(page);
    expect(collisions).toEqual([]);
  });
}

for (const theme of ["light", "dark"] as const) {
  test(`scope navigation fits the first load with scope context and leaf evidence in ${theme}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await routeCockpit(page, undefined, { rollupItemCount: 8 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await page.route("**/v1/graph/rollup?**", async route => {
      if (!new URL(route.request().url()).searchParams.has("node")) return route.fallback();
      const child = {
        id: "cred:slot", label: "API_TOKEN", entity_type: "credential", severity: "",
        is_container: false, has_children: false, direct_child_count: 0,
        aggregate: { descendant_count: 0, by_type: {}, severity_counts: { none: 1 }, worst_severity: "", worst_severity_rank: 0, internet_exposed: false, toxic_combo: false, exposed_count: 0, toxic_count: 0 },
      };
      return route.fulfill({ json: {
        scan_id: scanId, tenant_id: "default", created_at: createdAt, mode: "drilldown", filters: {},
        node: { id: "account:production", label: "Production account", entity_type: "cloud_account", severity: "critical" },
        children: [child, { ...child, id: "finding:high", label: "Credential exposure", entity_type: "misconfiguration", severity: "high" }], edges: [],
        summary: { direct_child_count: 2, matching_child_count: 2, returned_child_count: 2 },
        completeness: { returned: 2, total: 2, truncated: false, reason: "" },
      } });
    });
    await page.goto(`/graph?scan=${scanId}&rollup=1`);
    await expect(page.locator(".react-flow__node")).toHaveCount(8);
    await expect.poll(async () => {
      const canvas = await page.locator(".react-flow").boundingBox();
      const boxes = await page.locator(".react-flow__node").evaluateAll(nodes => nodes.map(n => {
        const r = n.getBoundingClientRect(); return { x: r.x, y: r.y, right: r.right, bottom: r.bottom };
      }));
      return !!canvas && boxes.every(r => r.x >= canvas.x && r.y >= canvas.y && r.right <= canvas.x + canvas.width + 1 && r.bottom <= canvas.y + canvas.height + 1);
    }).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`scope-fit-${theme}.png`), fullPage: true });
    await page.locator('.react-flow__node[data-id="account:production"]').click();
    await page.getByRole("button", { name: "Explore scope", exact: true }).click();
    const credential = page.locator('.react-flow__node[data-id="cred:slot"]');
    await expect(credential).toContainText("Inspect entity");
    await expect(credential).not.toContainText("contained entities");
    await expect(page.locator('.react-flow__node[data-id="account:production"]')).toHaveCount(0);
    await expect(page.getByTestId("graph-viewport-scope")).toContainText("Within Production account");
    await expect(page.locator('.react-flow__node[data-id="finding:high"]')).toContainText("High severity");
    await expect(page.locator('.react-flow__node[data-id="finding:high"]')).toContainText("Inspect finding");
    await page.screenshot({ path: testInfo.outputPath(`scope-parent-${theme}.png`), fullPage: true });
    await credential.click();
    await expect(page.getByTestId("graph-drawer-tab-overview")).toBeVisible();
    await expect(page.getByLabel("Scope details")).toHaveCount(0);
  });
}

test("unconnected proposal items remain usable on a narrow screen", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await routeCockpit(page, 36);
  await page.goto("/security-graph?lens=estate&rollup=0&scenario=scenario-private-endpoint&state=proposed");
  const panel = page.getByRole("region", { name: "Unconnected proposal items" });
  await expect(panel).toBeVisible();
  await expect(page.locator('.react-flow [data-id="proposal:scenario-private-endpoint:private-endpoint"]')).toHaveCount(0);
  const item = panel.getByRole("button", { name: /Private service endpoint/ });
  await item.scrollIntoViewIfNeeded();
  await expect(item).toBeInViewport();
  expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false);
  await page.screenshot({ path: testInfo.outputPath("scenario-unconnected-mobile.png"), fullPage: true });
  await item.click();
  await expect(page.getByTestId("graph-drawer-tab-overview")).toBeVisible();
});

test("embedded investigation opens the selected relationship receipt with the keyboard", async ({ page }) => {
  await routeCockpit(page);
  await page.goto("/security-graph?lens=attack-path");
  await expectCockpitVisible(page);
  const edge = page.getByTestId("security-graph-investigation").locator(".react-flow__edge").first();
  await expect(edge).toBeAttached();
  await edge.focus();
  await edge.press("Enter");
  await expect(page.getByRole("dialog", { name: "Relationship details" })).toBeVisible();
  await expect(page.getByRole("dialog", { name: "Relationship details" })).toContainText("does not establish execution");
});

for (const theme of ["light", "dark"] as const) {
  for (const width of [1440, 390]) {
    test(`lifecycle inventory and receipt remain usable ${theme} ${width}`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 900 });
      await page.addInitScript(theme => localStorage.setItem("agent-bom-theme", theme), theme);
      await routeCockpit(page);
      const graph = buildCockpitGraph();
      graph.edges.forEach((edge, index) => { edge.evidence = { tier: "static_scan", source: `lifecycle-receipt-${index}` }; });
      const counts = (type: string) => graph.nodes.filter(node => node.entity_type === type).length;
      const fixture = process.env.AGENT_BOM_LIFECYCLE_PROOF
        ? JSON.parse(readFileSync(process.env.AGENT_BOM_LIFECYCLE_PROOF, "utf8"))
        : { graph, nodes: [], edges: [], stats: { total_servers: counts("server"), total_packages: counts("package"),
          total_tools: counts("tool"), total_credentials: counts("credential"), total_vulnerabilities: counts("vulnerability") } };
      await page.route("**/v1/agents/lifecycle-proof/lifecycle", route => route.fulfill({ json: fixture }));
      await page.goto("/agents?name=lifecycle-proof&view=lifecycle");
      const view = page.getByTestId("agent-lifecycle-graph");
      await expect(view.getByRole("heading", { name: "Configured inventory" })).toBeVisible();
      await expect(view).toContainText("do not prove execution or effective access");
      await expect(view.locator(".react-flow__node").first()).toBeVisible();
      await expect(view.locator(".react-flow__edge").first()).toBeAttached();
      expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false);
      await page.screenshot({ path: testInfo.outputPath(`lifecycle-${theme}-${width}.png`), fullPage: true });
      const edge = view.locator(".react-flow__edge").first();
      const edgeId = await edge.getAttribute("data-id");
      const receipt = fixture.graph.edges.find((item: GraphEdge) => item.id === edgeId);
      expect(receipt).toBeTruthy();
      await edge.focus();
      await edge.press("Enter");
      const dialog = page.getByRole("dialog", { name: "Relationship details" });
      await expect(dialog).toBeVisible();
      await expect(dialog).toContainText("does not establish execution");
      await dialog.getByText("Technical details", { exact: true }).click();
      await dialog.getByText("Canonical identifiers", { exact: true }).click();
      await expect(dialog).toContainText(receipt.source);
      await expect(dialog).toContainText(receipt.target);
      await page.screenshot({ path: testInfo.outputPath(`lifecycle-receipt-${theme}-${width}.png`), fullPage: true });
      await dialog.getByRole("button", { name: "Close relationship details" }).click();
      await view.getByRole("button", { name: "Packages and advisories", exact: true }).click();
      await expect(view.getByRole("combobox", { name: "Inventory server" })).toBeVisible();
      await expect(view.locator('.react-flow__node[data-id]').first()).toBeVisible();
      await expect(view.locator('.react-flow__edge')).not.toHaveCount(0);
      if (width === 390) {
        await expect(view.locator(".react-flow__minimap")).toHaveCount(0);
        await view.getByRole("button", { name: "Next graph node" }).click();
        await expect(view).toContainText("Focused view · 2 of");
        const serverId = fixture.graph.nodes.find((node: GraphNode) => node.entity_type === "server").id;
        await expect.poll(() => view.locator(`.react-flow__node[data-id="${serverId}"]`).evaluate(node => {
          const box = node.getBoundingClientRect();
          const canvas = node.closest(".react-flow")!.getBoundingClientRect();
          return Math.abs(box.x + box.width / 2 - canvas.x - canvas.width / 2);
        })).toBeLessThan(20);
      }
      expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false);
      await page.screenshot({ path: testInfo.outputPath(`lifecycle-packages-${theme}-${width}.png`), fullPage: true });
    });
  }
}

test("embedded investigation opens the clicked relationship's exact receipt", async ({ page }) => {
  await routeCockpit(page);
  await page.goto("/security-graph?lens=attack-path");
  await expectCockpitVisible(page);
  const view = page.getByTestId("security-graph-investigation");
  await view.scrollIntoViewIfNeeded();
  const edge = view.locator(".react-flow__edge").first();
  const edgeId = await edge.getAttribute("data-id");
  const point = await edge.locator(".react-flow__edge-interaction").evaluate(element => {
    const path = element as SVGPathElement;
    const local = path.getPointAtLength(path.getTotalLength() * 0.35);
    const screen = new DOMPoint(local.x, local.y).matrixTransform(path.getScreenCTM()!);
    return { x: screen.x, y: screen.y };
  });
  await page.mouse.click(point.x, point.y);
  const dialog = page.getByRole("dialog", { name: "Relationship details" });
  await expect(dialog).toBeVisible();
  await dialog.getByText("Technical details", { exact: true }).click();
  await dialog.getByText("Canonical identifiers", { exact: true }).click();
  await expect(dialog).toContainText(edgeId!);
});

test("opening the full graph from a selected path keeps that path", async ({ page }) => {
  await routeCockpit(page);
  await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&path=top`);
  const detail = page.getByTestId("selected-exposure-path");
  await expect(detail.getByRole("heading", { name: "Claude Desktop → CVE-2025-7783" })).toBeVisible();
  const lineage = page.getByRole("link", { name: /^Open lineage/ }).first();
  await expect(lineage).toHaveAttribute("href", /^\/graph\?/);
  await expect(lineage).toHaveAttribute("href", /path=/);
  await lineage.click();
  await expect(page.getByTestId("selected-exposure-path")).toHaveCount(0);
  await expect(page.locator(".react-flow__node")).toHaveCount(4);
  for (const id of ["agent:desktop", "server:github", "pkg:form-data", "cve:form-data"]) {
    await expect(page.locator(`.react-flow__node[data-id="${id}"]`)).toBeVisible();
  }
});
