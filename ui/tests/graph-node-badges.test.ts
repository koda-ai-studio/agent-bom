import { describe, expect, it } from "vitest";

import { badgeLegendItems, nodeBadges, type NodeBadgeInput } from "@/lib/graph-node-badges";

function input(overrides: Partial<NodeBadgeInput>): NodeBadgeInput {
  return { nodeType: "container", ...overrides };
}

describe("nodeBadges", () => {
  it("returns nothing for a node without recorded attributes", () => {
    expect(nodeBadges(input({}))).toEqual({ badges: [], ring: null });
  });

  it("derives the environment tier from the recorded dimension, then attributes", () => {
    expect(nodeBadges(input({ dimensions: { environment: "Production" } })).badges)
      .toEqual([expect.objectContaining({ kind: "environment", value: "prod", label: "PROD", raw: "Production" })]);
    expect(nodeBadges(input({ attributes: { environment: "stg" } })).badges[0])
      .toMatchObject({ value: "staging", label: "STAGING" });
    expect(nodeBadges(input({ dimensions: { environment: "sandbox" } })).badges[0])
      .toMatchObject({ value: "dev", label: "DEV" });
  });

  it("never invents a tier for an unrecognised environment value", () => {
    expect(nodeBadges(input({ dimensions: { environment: "blue-42" } })).badges).toEqual([]);
  });

  it("shows the environment only on deployable assets, not on every package or finding", () => {
    const dimensions = { environment: "prod" };
    expect(nodeBadges(input({ nodeType: "package", dimensions })).badges).toEqual([]);
    expect(nodeBadges(input({ nodeType: "vulnerability", dimensions })).badges).toEqual([]);
    expect(nodeBadges(input({ nodeType: "environment", dimensions })).badges).toHaveLength(1);
  });

  it("derives the package ecosystem from the field, dimension, attribute or purl", () => {
    expect(nodeBadges(input({ nodeType: "package", ecosystem: "pypi" })).badges[0]).toMatchObject({ kind: "ecosystem", label: "PyPI" });
    expect(nodeBadges(input({ nodeType: "package", dimensions: { ecosystem: "npm" } })).badges[0]).toMatchObject({ label: "npm" });
    expect(nodeBadges(input({ nodeType: "package", attributes: { purl: "pkg:golang/github.com/x/y@v1.2.0" } })).badges[0])
      .toMatchObject({ label: "Go", value: "golang" });
    expect(nodeBadges(input({ nodeType: "package", attributes: { purl: "pkg:maven/org.x/y@1" } })).badges[0]).toMatchObject({ label: "Maven" });
    expect(nodeBadges(input({ nodeType: "package", attributes: { purl: "not-a-purl" } })).badges).toEqual([]);
    expect(nodeBadges(input({ nodeType: "package", ecosystem: "made-up" })).badges).toEqual([]);
    expect(nodeBadges(input({ nodeType: "vulnerability", attributes: { ecosystem: "pypi" } })).badges).toEqual([]);
  });

  it("derives a cloud provider only from recognised provider values", () => {
    expect(nodeBadges(input({ nodeType: "account", dimensions: { cloud_provider: "aws" } })).badges[0])
      .toMatchObject({ kind: "provider", label: "AWS" });
    expect(nodeBadges(input({ nodeType: "dataStore", attributes: { provider: "Snowflake" } })).badges[0]).toMatchObject({ label: "Snowflake" });
    expect(nodeBadges(input({ nodeType: "cluster", attributes: { cloud_provider: "k8s" } })).badges[0]).toMatchObject({ label: "K8s" });
    expect(nodeBadges(input({ nodeType: "model", attributes: { provider: "customer-managed" } })).badges).toEqual([]);
  });

  it("orders provider, environment and ecosystem badges consistently with accessible text", () => {
    const { badges } = nodeBadges(input({
      nodeType: "container",
      dimensions: { environment: "prod", cloud_provider: "gcp" },
    }));
    expect(badges.map((badge) => badge.kind)).toEqual(["provider", "environment"]);
    for (const badge of badges) expect(badge.description.length).toBeGreaterThan(badge.label.length);
  });

  it("rings non-finding nodes that carry findings or an assessed risk", () => {
    expect(nodeBadges(input({ nodeType: "package", severity: "critical", vulnCount: 2 })).ring)
      .toMatchObject({ severity: "critical" });
    expect(nodeBadges(input({ nodeType: "server", severity: "High", riskAssessment: { status: "assessed", basis: "b", scope: "s" } })).ring)
      .toMatchObject({ severity: "high" });
  });

  it("does not ring findings themselves, unassessed nodes, or unknown severities", () => {
    expect(nodeBadges(input({ nodeType: "vulnerability", severity: "critical", vulnCount: 1 })).ring).toBeNull();
    expect(nodeBadges(input({ nodeType: "package", severity: "high" })).ring).toBeNull();
    expect(nodeBadges(input({ nodeType: "package", severity: "none", vulnCount: 3 })).ring).toBeNull();
    expect(nodeBadges(input({ nodeType: "package", severity: "unknown", vulnCount: 3 })).ring).toBeNull();
  });
});

describe("badgeLegendItems", () => {
  it("lists exactly the badges and rings present on visible nodes, once each", () => {
    const items = badgeLegendItems([
      { data: input({ nodeType: "container", dimensions: { environment: "prod", cloud_provider: "aws" } }) },
      { data: input({ nodeType: "cluster", dimensions: { environment: "production", cloud_provider: "aws" } }) },
      { data: input({ nodeType: "package", ecosystem: "npm", severity: "critical", vulnCount: 1 }) },
      { data: { label: "no data" } },
    ]);
    expect(items.map((item) => item.label)).toEqual([
      "AWS provider",
      "Production environment",
      "npm ecosystem",
      "Critical severity ring",
    ]);
    expect(items.every((item) => item.kind === "badge" && item.layer === "badge")).toBe(true);
  });

  it("is empty for a graph without badge data", () => {
    expect(badgeLegendItems([{ data: input({}) }])).toEqual([]);
  });
});
