import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AttackPathCorrelationProof } from "@/components/attack-path-correlation-proof";
import type { GraphAttackPath } from "@/lib/api-types";
import type { UnifiedNode } from "@/lib/graph-schema";

describe("AttackPathCorrelationProof", () => {
  it("summarizes verified proof and keeps exact per-hop receipts inspectable", () => {
    const digest = "sha256:7d3e21c47d244111d7502503e9868ce01f2dfd77f0d71d876a3a8da1f477d58a";
    const nodes = [
      { id: "service:api", entity_type: "server", label: "Public API" },
      { id: "container:api", entity_type: "container", label: `reference-api@${digest}` },
      { id: "package:pillow", entity_type: "package", label: "pillow@9.0.0" },
      { id: "vulnerability:webp", entity_type: "vulnerability", label: "CVE-2023-4863" },
    ] as UnifiedNode[];
    const path = {
      source: "service:api",
      target: "vulnerability:webp",
      reachability: "confirmed",
      analysis: { status: "complete" },
      hops: nodes.map((node) => node.id),
      edges: ["contains", "contains", "vulnerable_to"],
      hop_evidence: [
        {
          source_node_id: "service:api",
          target_node_id: "container:api",
          relationship: "contains",
          relationship_provenance: "recorded",
          correlation_identity_status: "current",
          source_snapshot_ids: ["reference-kubernetes-iac-scan"],
          evidence_tier: "modeled_infrastructure",
          confidence: 1,
          freshness: "fresh",
          runtime_observed_state: "not_observed",
          direction: "directed",
          traversable: true,
          complete: true,
          truncated: false,
        },
        {
          source_node_id: "container:api",
          target_node_id: "package:pillow",
          relationship: "contains",
          relationship_provenance: "recorded",
          correlation_identity_status: "current",
          source_snapshot_ids: ["reference-image-sbom-scan"],
          evidence_tier: "static_scan",
          confidence: 1,
          freshness: "fresh",
          runtime_observed_state: "not_observed",
          direction: "directed",
          traversable: true,
          complete: true,
          truncated: false,
        },
        {
          source_node_id: "package:pillow",
          target_node_id: "vulnerability:webp",
          relationship: "vulnerable_to",
          relationship_provenance: "recorded",
          correlation_identity_status: "current",
          source_snapshot_ids: ["reference-image-sbom-scan"],
          evidence_tier: "static_scan",
          confidence: 1,
          freshness: "fresh",
          runtime_observed_state: "not_observed",
          direction: "directed",
          traversable: true,
          complete: true,
          truncated: false,
        },
      ],
    } as GraphAttackPath;

    render(<AttackPathCorrelationProof path={path} nodes={nodes} />);

    expect(screen.getByText("Hop receipts complete")).toBeInTheDocument();
    expect(screen.getByText("Read from files or configuration")).toBeInTheDocument();
    expect(screen.queryByText("Path verified")).not.toBeInTheDocument();
    expect(screen.getByText("3/3 directed traversable hops evidenced")).toBeInTheDocument();
    expect(screen.getByText(`reference-api@${digest}`)).toBeInTheDocument();
    expect(screen.getByText("pillow@9.0.0")).toBeInTheDocument();
    expect(screen.getByText("CVE-2023-4863")).toBeInTheDocument();
    expect(screen.queryByText("reference-kubernetes-iac-scan")).not.toBeInTheDocument();
    expect(screen.getByText("Inspect 3 hop receipts")).toBeInTheDocument();

    fireEvent.click(screen.getByText("Inspect 3 hop receipts"));
    fireEvent.click(screen.getByRole("button", { name: /1\. Public API/ }));
    expect(screen.getByText("reference-kubernetes-iac-scan")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /2\. reference-api/ }));
    expect(screen.queryByText("reference-kubernetes-iac-scan")).not.toBeInTheDocument();
    expect(screen.getByText("reference-image-sbom-scan")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /3\. pillow@9.0.0 → CVE-2023-4863/ })).toHaveAttribute("aria-expanded", "false");
  });

  it("does not call an incomplete or non-traversable chain verified", () => {
    const path = {
      source: "service:api",
      target: "package:pillow",
      hops: ["service:api", "container:api", "package:pillow"],
      edges: ["contains", "contains"],
      hop_evidence: [
        {
          source_node_id: "service:api",
          target_node_id: "container:api",
          relationship: "contains",
          relationship_provenance: "recorded",
          correlation_identity_status: "current",
          source_snapshot_ids: ["iac-scan"],
          evidence_tier: "modeled_infrastructure",
          confidence: 1,
          freshness: "stale_allowed",
          runtime_observed_state: "not_observed",
          direction: "directed",
          traversable: false,
          complete: true,
          truncated: false,
        },
      ],
    } as GraphAttackPath;

    render(<AttackPathCorrelationProof path={path} />);

    expect(screen.getByText("Hop receipts incomplete")).toBeInTheDocument();
    expect(screen.queryByText("Directed-hop receipt count unavailable")).not.toBeInTheDocument();
    expect(screen.getByText("0/2 hops fully evidenced · 1 of 2 hop receipts recorded")).toBeInTheDocument();
    expect(screen.getByText("Gaps: not traversable, freshness not established, path analysis not recorded")).toBeInTheDocument();
    expect(screen.getByText("Stale allowed")).toHaveClass("text-amber-700");
    expect(screen.queryByText("Path verified")).not.toBeInTheDocument();
  });

  it("does not call a fully traversable stale-allowed chain verified", () => {
    const path = {
      source: "service:api",
      target: "package:pillow",
      reachability: "likely",
      hops: ["service:api", "container:api", "package:pillow"],
      edges: ["contains", "contains"],
      hop_evidence: [
        {
          source_node_id: "service:api",
          target_node_id: "container:api",
          relationship: "contains",
          relationship_provenance: "recorded",
          correlation_identity_status: "current",
          source_snapshot_ids: ["iac-scan"],
          evidence_tier: "modeled_infrastructure",
          confidence: 1,
          freshness: "stale_allowed",
          runtime_observed_state: "not_observed",
          direction: "directed",
          traversable: true,
          complete: true,
          truncated: false,
        },
        {
          source_node_id: "container:api",
          target_node_id: "package:pillow",
          relationship: "contains",
          relationship_provenance: "recorded",
          correlation_identity_status: "current",
          source_snapshot_ids: ["sbom-scan"],
          evidence_tier: "static_scan",
          confidence: 1,
          freshness: "fresh",
          runtime_observed_state: "not_observed",
          direction: "directed",
          traversable: true,
          complete: true,
          truncated: false,
        },
      ],
    } as GraphAttackPath;

    render(<AttackPathCorrelationProof path={path} />);

    expect(screen.getByText("Hop receipts incomplete")).toBeInTheDocument();
    expect(screen.getByText("Stale allowed")).toBeInTheDocument();
    expect(screen.queryByText("Path verified")).not.toBeInTheDocument();
  });
});

it("discloses missing canonical path nodes instead of silently omitting anchors", () => {
  const path = {source: "a", target: "missing", hops: ["a", "missing"], edges: ["contains"]} as GraphAttackPath;
  render(<AttackPathCorrelationProof path={path} nodes={[{id: "a", label: "image", entity_type: "container"} as UnifiedNode]} />);
  expect(screen.getByText("1 path nodes unavailable")).toBeInTheDocument();
  expect(screen.getByText("image")).toBeInTheDocument();
  expect(screen.getByText("Hop receipts incomplete")).toBeInTheDocument();
});

it("renders malformed legacy receipts without granting proof", () => {
  const path = {source: "a", target: "b", hops: ["a", "b"], edges: ["uses"], hop_evidence: [null, {source_snapshot_ids: null}]} as unknown as GraphAttackPath;
  render(<AttackPathCorrelationProof path={path} />);
  expect(screen.getByText("Hop receipts incomplete")).toBeInTheDocument();
});

it("shows the server ranking reasons without deriving a browser score", () => {
  const path = { source: "a", target: "b", hops: ["a", "b"], edges: [], hop_evidence: [] } as unknown as GraphAttackPath;
  render(<AttackPathCorrelationProof path={path} riskReasons={[{ kind: "credential", label: "Credential association", detail: "Recorded credential edge raises review priority; access remains unverified." }]} />);
  expect(screen.getByText("Why this path ranks here")).toBeInTheDocument();
  fireEvent.click(screen.getByText("Why this path ranks here"));
  expect(screen.getByText(/Recorded credential edge raises review priority/)).toBeVisible();
});

it("renders the server's ranking factors when no fix-first card explains the order", () => {
  const path = {
    source: "agent:a", target: "vuln:v", hops: ["agent:a", "vuln:v"], edges: ["uses"], hop_evidence: [],
    ranking_factors: {
      order: ["evidence_tier", "is_kev", "severity", "evidence_confidence", "composite_risk", "credential_count"],
      evidence_tier: 3, is_kev: true, severity: "unknown", severity_scored: false, evidence_confidence: "structural",
      composite_risk: 90.6, credential_count: 1,
      reasons: ["Evidence tier 3: finding reached from an agent or through a credential.", "No scored finding on the path (unscored)."],
    },
  } as unknown as GraphAttackPath;
  render(<AttackPathCorrelationProof path={path} />);
  fireEvent.click(screen.getByText("Why this path ranks here"));
  const factors = screen.getByTestId("attack-path-ranking-factors");
  expect(factors).toHaveTextContent("Tier 3");
  expect(factors).toHaveTextContent("KEV yes");
  expect(factors).toHaveTextContent("Severity unscored");
  expect(factors).toHaveTextContent("Evidence topology only");
  expect(factors).toHaveTextContent("Risk 90.6/100");
  expect(screen.getByText("No scored finding on the path (unscored).")).toBeVisible();
  expect(screen.queryByText(/without ranking explanations/)).not.toBeInTheDocument();
});

it("keeps the receipt summary consistent with the receipts listed for inspection", () => {
  const receipt = (source: string, target: string, relationship: string) => ({
    source_node_id: source, target_node_id: target, relationship, source_snapshot_ids: ["scan-1"],
    relationship_provenance: "unavailable", correlation_identity_status: "current", evidence_tier: "static_scan",
    confidence: 1, freshness: "unknown", runtime_observed_state: "not_observed", direction: "directed",
    traversable: true, complete: false, truncated: false,
  });
  const path = {
    source: "agent:a", target: "finding:f", reachability: "unknown", analysis: { status: "complete" },
    hops: ["agent:a", "server:s", "cred:c", "finding:f"], edges: ["uses", "exposes_cred", "vulnerable_to"],
    hop_evidence: [receipt("agent:a", "server:s", "uses"), receipt("server:s", "cred:c", "exposes_cred"), receipt("cred:c", "finding:f", "vulnerable_to")],
  } as unknown as GraphAttackPath;
  render(<AttackPathCorrelationProof path={path} />);
  expect(screen.getByText("Hop receipts incomplete")).toBeInTheDocument();
  expect(screen.queryByText("Directed-hop receipt count unavailable")).not.toBeInTheDocument();
  expect(screen.getByText("0/3 hops fully evidenced · 3 of 3 hop receipts recorded")).toBeInTheDocument();
  expect(screen.getByText("Gaps: receipt marked incomplete, freshness not established, relationship provenance unavailable")).toBeInTheDocument();
  expect(screen.getByText("Inspect 3 hop receipts")).toBeInTheDocument();
});
