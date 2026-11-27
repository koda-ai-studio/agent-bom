import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

import {
  DEMO_AGENT_SPECS,
  buildBlastRadius,
  buildGraph,
  contextGraph,
  contextLateralRisk,
  graphScenarioComparison,
  hopsAreConnected,
  pathRisk,
} from "../scripts/product-proof-graph.mjs";

type Advisory = { id: string; package: string; version: string; severity: string; cvss_score: number; fixed_version: string };
const advisories: Advisory[] = JSON.parse(fs.readFileSync(path.join(process.cwd(), "fixtures/gallery-advisories.json"), "utf8")).advisories;
const advisory = (id: string) => advisories.find((item) => item.id === id)!;

describe("seeded product-proof graph", () => {
  const graph = buildGraph();
  const byId = new Map(graph.nodes.map((item) => [item.id, item]));

  it("reports severity counts that equal the seeded nodes", () => {
    const counted = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
    for (const item of graph.nodes) if (item.severity in counted) counted[item.severity] = (counted[item.severity] ?? 0) + 1;
    expect(graph.stats.severity_counts).toEqual(counted);
    expect(graph.stats.total_nodes).toBe(graph.nodes.length);
    expect(graph.stats.total_edges).toBe(graph.edges.length);
  });

  it("scores advisory and package nodes from the verified advisory facts", () => {
    for (const item of graph.nodes.filter((entry) => entry.entity_type === "vulnerability")) {
      expect([item.label, item.severity, item.risk_score]).toEqual([item.label, advisory(item.label).severity, advisory(item.label).cvss_score]);
    }
    for (const link of graph.edges.filter((entry) => entry.relationship === "vulnerable_to")) {
      const pkg = byId.get(link.source)!;
      const cve = byId.get(link.target)!;
      expect(pkg.label).toBe(`${advisory(cve.label).package}@${advisory(cve.label).version}`);
      expect([pkg.label, pkg.severity]).toEqual([pkg.label, cve.severity]);
    }
  });

  it("puts every attack path on the 0-100 scale, derived from its hops, with recorded edges", () => {
    expect(graph.attack_paths.length).toBe(graph.stats.attack_path_count);
    for (const item of graph.attack_paths) {
      expect(item.composite_risk).toBeGreaterThan(10);
      expect(item.composite_risk).toBeLessThanOrEqual(100);
      expect(item.composite_risk).toBe(pathRisk(graph.nodes, item.hops));
      if (item.source === "container:copilot-portal") expect(item.hops).toEqual(["container:copilot-portal", "pkg:next", "cve:next"]);
      else expect(item.hops.length).toBeGreaterThanOrEqual(4);
      expect(item.hops.length).toBeLessThanOrEqual(7);
      expect(hopsAreConnected(graph.edges, item.hops)).toBe(true);
      expect(item.edges).not.toContain("related");
      const pathHops: string[] = item.hops;
      const pathCves = pathHops.map((id) => byId.get(id)!).filter((node) => node.entity_type === "vulnerability").map((node) => node.label);
      expect(item.vuln_ids).toEqual(pathCves);
      expect(item.severity).toBe(pathCves.length ? advisory(pathCves[0]).severity : byId.get(item.target)!.severity);
    }
    expect(graph.stats.max_attack_path_risk).toBe(Math.max(...graph.attack_paths.map((item) => item.composite_risk)));
    expect(graph.stats.interaction_risk_count).toBe(graph.interaction_risks.length);
  });

  it("ranks the medium urllib3 path below the critical and data paths", () => {
    const risk = (cve: string) => graph.attack_paths.find((item) => item.target === cve)!.composite_risk;
    expect(risk("cve:urllib3")).toBe(advisory("CVE-2024-37891").cvss_score * 10);
    expect(risk("cve:urllib3")).toBeLessThan(risk("cve:next"));
  });

  it("names credentials by env-var reference and backs every shared credential with a node", () => {
    const labels = graph.nodes.map((item) => item.label);
    expect(labels).toContain("GITHUB_ENTERPRISE_TOKEN");
    expect(labels).not.toContain("DEMO_CRED_REF");
    for (const link of graph.edges.filter((item) => item.relationship === "shares_cred")) {
      const credential = (link.evidence as { credential?: string }).credential;
      const credentialNode = graph.nodes.find((item) => item.entity_type === "credential" && item.label === credential);
      expect(credentialNode).toBeDefined();
      for (const agent of [link.source, link.target]) {
        const servers = graph.edges.filter((item) => item.source === agent && item.relationship === "uses").map((item) => item.target);
        expect(graph.edges.some((item) => servers.includes(item.source) && item.target === credentialNode!.id)).toBe(true);
      }
    }
  });

  it("keeps next on a web workload the first path reaches, not on the GitHub MCP server", () => {
    const owners = graph.edges.filter((item) => item.target === "pkg:next" && item.relationship === "depends_on").map((item) => item.source);
    expect(owners).toEqual(["container:copilot-portal"]);
    expect(graph.attack_paths[0]?.hops).toContain("container:copilot-portal");
  });

  it("marks entry, privilege and sensitive-data badges with backend attribute names", () => {
    const attributes = (id: string) => byId.get(id)!.attributes as Record<string, unknown>;
    expect(attributes("container:copilot-portal").internet_exposed).toBe(true);
    expect(attributes("role:prod-admin").admin_equivalent).toBe(true);
    expect(attributes("dataset:finance-docs").data_classification).toBe("confidential");
  });

  it("uses one display form for agent labels", () => {
    const agentLabels = graph.nodes.filter((item) => item.entity_type === "agent").map((item) => item.label);
    expect(agentLabels).toEqual(["Developer Copilot", "SRE Runbook Agent", "Finance RAG Agent"]);
    expect(contextGraph().nodes.filter((item) => item.kind === "agent").map((item) => item.label)).toEqual(agentLabels);
  });
});

describe("seeded scenario comparison", () => {
  it("cuts a real hop and derives the deltas from the modeled graph", () => {
    const graph = buildGraph();
    const comparison = graphScenarioComparison(graph);
    const [removed] = comparison.difference.edges_removed;
    expect(graph.edges.some((item) => item.id === removed)).toBe(true);
    const cutPaths = graph.attack_paths.filter((item) => !hopsAreConnected(comparison.proposed.edges, item.hops));
    expect(cutPaths.length).toBeGreaterThan(0);
    const modeled = graph.attack_paths.filter((item) => hopsAreConnected(comparison.proposed.edges, item.hops));
    expect(comparison.comparison.modeled_path_count).toBe(modeled.length);
    expect(comparison.comparison.path_delta).toBe(modeled.length - graph.attack_paths.length);
    const maxRisk = (paths: typeof modeled) => Math.max(0, ...paths.map((item) => item.composite_risk));
    expect(comparison.comparison.risk_delta).toBe(maxRisk(modeled) - maxRisk(graph.attack_paths));
    expect(comparison.difference.touched_observed_path_count).toBe(cutPaths.length);
    expect(comparison.scenario.name).toContain(advisory("CVE-2025-29927").fixed_version);
    expect(comparison.proposed.edge_count).toBe(comparison.proposed.edges.length);
  });
});

describe("seeded context graph", () => {
  it("keeps lateral paths on the backend 0-10 scale and derives the stats", () => {
    const context = contextGraph();
    for (const item of context.lateral_paths) {
      expect(item.composite_risk).toBe(contextLateralRisk(context.nodes, context.edges, item.hops));
      expect(item.composite_risk).toBeLessThanOrEqual(10);
    }
    expect(context.stats.highest_path_risk).toBe(Math.max(...context.lateral_paths.map((item) => item.composite_risk)));
    expect(context.stats.shared_credential_count).toBe(context.edges.filter((item) => item.kind === "shares_credential").length);
    expect(context.stats.total_nodes).toBe(context.nodes.length);
  });
});

describe("seeded blast radius", () => {
  it("takes severity, score and package from the advisory for every entry", () => {
    const entries = buildBlastRadius();
    for (const item of entries) {
      const facts = advisory(item.vulnerability_id);
      expect([item.vulnerability_id, item.severity, item.cvss_score, item.risk_score, item.package, item.fixed_version])
        .toEqual([facts.id, facts.severity, facts.cvss_score, facts.cvss_score, `${facts.package}@${facts.version}`, facts.fixed_version]);
      expect(item.blast_score).toBe(Math.round(facts.cvss_score * 10));
    }
    const ids = entries.map((item) => item.vulnerability_id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const spec of DEMO_AGENT_SPECS) if (spec.cve) expect(ids).toContain(spec.cve[0]);
  });
});
