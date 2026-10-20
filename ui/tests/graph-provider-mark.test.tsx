import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import { lineageNodeTypes } from "@/components/lineage-nodes";
import { GraphProviderMark } from "@/components/graph-provider-mark";
import { GraphScopeNode } from "@/components/graph-scope-node";
import { ScopeBreadcrumbChip } from "@/components/graph-scope-breadcrumb";
import { SegmentedLabel } from "@/components/graph-segmented-label";
import { providerMarkBasis, scopeProvider } from "@/lib/provider-basis";
import { nameScopeCrumbs } from "@/lib/graph-scope-crumbs";
import { entitySource } from "@/lib/agent-source";
import { NODE_BADGE_CLASSES } from "@/lib/graph-node-badges";
import type { GraphRollupContainer } from "@/lib/api-types";

const aws = entitySource({ nodeType: "cluster", dimensions: { cloud_provider: "aws" } })!;

function scope(overrides: Partial<GraphRollupContainer> = {}): GraphRollupContainer {
  return {
    id: "env:gcp:analytics:production", label: "production", entity_type: "environment", severity: "high",
    is_container: true, has_children: true, direct_child_count: 3,
    aggregate: { descendant_count: 12, by_type: {}, severity_counts: {}, worst_severity: "high", worst_severity_rank: 3, internet_exposed: false, toxic_combo: false, exposed_count: 0, toxic_count: 0 },
    ...overrides,
  } as GraphRollupContainer;
}

describe("provider basis", () => {
  it("states a declared provider plainly", () => {
    expect(providerMarkBasis(aws, {})).toEqual({ inherited: false, title: "Source: AWS" });
  });

  it("names the recorded scope an inherited provider came from", () => {
    const basis = providerMarkBasis(aws, {
      cloud_provider_basis: "inherited:hosts",
      cloud_provider_source: { node_id: "cluster:payments", label: "payments-eks", entity_type: "cluster" },
    });
    expect(basis).toEqual({ inherited: true, title: "Source: AWS · inherited from AWS cluster payments-eks" });
  });

  it("never claims inheritance without a recorded source", () => {
    expect(providerMarkBasis(aws, { cloud_provider_basis: "inherited:hosts" })).toEqual({ inherited: true, title: "Source: AWS · inherited" });
  });

  it("resolves a scope's provider only from the roll-up payload", () => {
    expect(scopeProvider(scope({ cloud_provider: "gcp" }))?.label).toBe("Google Cloud");
    expect(scopeProvider(scope({ label: "aws-prod" }))).toBeNull();
    expect(scopeProvider(scope({ cloud_provider: "not-a-cloud" }))).toBeNull();
  });
});

describe("graph provider mark", () => {
  it("renders a themed disc sized to the glyph with a solid border when declared", () => {
    render(<GraphProviderMark source={aws} attributes={{}} />);
    const mark = screen.getByRole("img", { name: "Source: AWS" });
    expect(mark).toHaveAttribute("data-graph-source-badge", "true");
    expect(mark).toHaveAttribute("data-provider-basis", "declared");
    expect(mark.className).toContain("graph-provider-mark");
    expect(mark.getAttribute("style") ?? "").not.toMatch(/#fff|white/i);
    expect(mark.querySelector('img[src="/logos/aws.svg"]')).not.toBeNull();
  });

  it("marks an inherited provider with a distinct variant and a basis tooltip", () => {
    render(<GraphProviderMark source={aws} attributes={{ cloud_provider_basis: "inherited:contains", cloud_provider_source: { label: "prod-workloads", entity_type: "account" } }} />);
    const mark = screen.getByRole("img", { name: "Source: AWS · inherited from AWS account prod-workloads" });
    expect(mark).toHaveAttribute("data-provider-basis", "inherited");
    expect(mark).toHaveAttribute("title", "Source: AWS · inherited from AWS account prod-workloads");
  });

  it("is what an asset node shows, and the provider is not repeated as a text chip", () => {
    const Renderer = lineageNodeTypes.containerNode;
    const { container } = render(<ReactFlowProvider><Renderer data={{
      label: "ledger-worker", nodeType: "container",
      dimensions: { cloud_provider: "aws", environment: "staging" },
      attributes: { cloud_provider_basis: "inherited:hosts", cloud_provider_source: { label: "payments-eks", entity_type: "cluster" } },
    }} /></ReactFlowProvider>);
    const mark = screen.getByRole("img", { name: /inherited from AWS cluster payments-eks/ });
    expect(mark.parentElement).toHaveClass("graph-entity-glyph");
    expect(container.querySelector('[data-node-badge="provider"]')).toBeNull();
    expect(container.querySelector('[data-node-badge="environment"]')).toHaveTextContent("STAGING");
  });
});

describe("scope card and breadcrumb", () => {
  it("puts the provider next to the scope type in the card eyebrow", () => {
    render(<ReactFlowProvider><GraphScopeNode item={scope({ cloud_provider: "gcp", cloud_provider_basis: "declared" })} /></ReactFlowProvider>);
    const eyebrow = screen.getByTestId("graph-scope-eyebrow");
    expect(eyebrow).toHaveTextContent("Environment · Google Cloud");
    expect(eyebrow.querySelector('[data-agent-source="gcp"]')).not.toBeNull();
  });

  it("keeps the eyebrow honest when the scope has no provider", () => {
    render(<ReactFlowProvider><GraphScopeNode item={scope({ label: "aws-looking-name" })} /></ReactFlowProvider>);
    expect(screen.getByTestId("graph-scope-eyebrow")).toHaveTextContent(/^Environment$/);
    expect(screen.getByTestId("graph-scope-eyebrow").querySelector("[data-agent-source]")).toBeNull();
  });

  it("carries the provider mark on the breadcrumb chip", () => {
    render(<ScopeBreadcrumbChip crumb={{ id: "account:aws:1", label: "prod-workloads", cloudProvider: "aws" }} onClick={() => {}} />);
    const chip = screen.getByRole("button", { name: /prod-workloads/ });
    expect(chip.querySelector('[data-agent-source="aws"]')).not.toBeNull();
    render(<ScopeBreadcrumbChip crumb={{ id: "repo:1", label: "payments" }} onClick={() => {}} />);
    expect(screen.getByRole("button", { name: "payments" }).querySelector("[data-agent-source]")).toBeNull();
  });

  it("names crumbs from the server without churning an unchanged stack", () => {
    const stack = [{ id: "a", label: "a" }, { id: "b", label: "Billing", cloudProvider: "aws" }];
    expect(nameScopeCrumbs(stack, { id: "b", label: "Billing", cloud_provider: "aws" })).toBe(stack);
    expect(nameScopeCrumbs(stack, null)).toBe(stack);
    expect(nameScopeCrumbs(stack, { id: "a", label: "Analytics", cloud_provider: "gcp" })).toEqual([
      { id: "a", label: "Analytics", cloudProvider: "gcp" }, stack[1],
    ]);
  });

  it("preserves inherited provider provenance when a scope becomes a breadcrumb", () => {
    const named = { id: "env:prod", label: "Production", cloud_provider: "aws", cloud_provider_basis: "inherited:contains" };
    const crumbs = nameScopeCrumbs([{ id: named.id, label: named.id }], named);
    render(<ScopeBreadcrumbChip crumb={crumbs[0]!} onClick={() => {}} />);
    expect(screen.getByRole("img", { name: "Source: AWS · inherited" })).toHaveAttribute("data-provider-basis", "inherited");
    expect(nameScopeCrumbs(crumbs, named)).toBe(crumbs);
  });
});

describe("node chips", () => {
  it("use opaque borders: translucent color-mix edges anti-alias into cyan specks", () => {
    for (const styles of Object.values(NODE_BADGE_CLASSES)) for (const classes of Object.values(styles)) {
      expect(classes.split(/\s+/).filter(name => /(^|:)border-[a-z]+-\d+\/\d+$/.test(name)), classes).toEqual([]);
    }
  });
});

describe("segmented label", () => {
  it("offers breaks only at segment boundaries and balances the lines", () => {
    const { container } = render(<SegmentedLabel text="customer-pii-bucket" />);
    expect(container.querySelectorAll("wbr")).toHaveLength(2);
    const host = container.firstElementChild as HTMLElement;
    expect(host.className).toContain("[text-wrap:balance]");
    expect(host.className).not.toContain("overflow-wrap:anywhere");
    expect(host).toHaveTextContent("customer-pii-bucket");
  });
});

describe("provider marks that are not legible at badge size", () => {
  it("draw Okta as its monogram instead of a bare ring", () => {
    const source = entitySource({ nodeType: "user", dimensions: { cloud_provider: "okta" } })!;
    const { container } = render(<GraphProviderMark source={source} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toBe("Ok");
    expect(container.querySelector("[data-graph-source-badge]")?.getAttribute("aria-label")).toBe("Source: Okta");
  });
});
