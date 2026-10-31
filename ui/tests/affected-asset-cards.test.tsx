import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AffectedAssetCards } from "@/components/advisories/affected-asset-cards";
import type { AdvisoryAffectedResponse } from "@/lib/advisory-affected";

import php2shell from "./fixtures/php2shell-affected.json";

const rows = (php2shell as unknown as AdvisoryAffectedResponse).rows;

function order(card: HTMLElement, needles: string[]): number[] {
  const text = card.textContent ?? "";
  return needles.map(needle => text.indexOf(needle));
}

describe("AffectedAssetCards", () => {
  it("stacks asset, verdict with detail, installed → patch target, evidence, then the blast-radius link", () => {
    render(<AffectedAssetCards rows={rows} />);
    const cards = screen.getAllByTestId("affected-asset-card");
    expect(cards).toHaveLength(3);

    const [affected, distro, clean] = cards as [HTMLElement, HTMLElement, HTMLElement];
    const positions = order(distro, [
      "abtest/php-debian:12",
      "Possibly affected — verify distro advisory",
      "distro package php8.2-cli 8.2.29-1~deb12u1 ships php",
      "php8.2-cli 8.2.29-1~deb12u1",
      "patch targetverify distro advisory",
      "Operator advisory · last observed",
      "Blast radius",
    ]);
    expect(positions.every(position => position >= 0)).toBe(true);
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);

    expect(within(affected).getByTestId("verdict-badge")).toHaveTextContent("Affected");
    expect(within(affected).getByTestId("patch-target")).toHaveTextContent("8.3.36");
    expect(within(affected).getByRole("link", { name: "Blast radius for php 8.3.30 on php:8.3.30-cli" }))
      .toHaveAttribute("href", "/security-graph?lens=attack-path&scan=scan-php-8.3.30&node=pkg%3Ageneric%3Aphp%408.3.30");
    expect(within(clean).getByTestId("patch-target")).toHaveTextContent("Not needed");
  });
  it("shows a readable package label while preserving distinct occurrence identities and graph targets", () => {
    const standalone = ["first", "second"].map(scope => {
      const node = `pkg:pypi:pillow@9.0.0:image:${scope}`;
      return { ...rows[0]!, asset: { agent: "", server: "", node_id: node }, asset_label: node,
        asset_type: "package", asset_node_id: node, scan_id: "scan-fixture",
        package: { name: "pillow", version: "9.0.0", ecosystem: "pypi" }, installed_version: "9.0.0",
        graph: { package_node_id: node, server_node_id: null, agent_node_id: null } };
    });
    render(<AffectedAssetCards rows={standalone} />);
    const cards = screen.getAllByTestId("affected-asset-card");
    expect(cards).toHaveLength(2);
    cards.forEach((card, i) => {
      expect(within(card).getByText("pillow@9.0.0")).toBeVisible();
      expect(within(card).getByText("Package occurrence · owner not recorded")).toBeVisible();
      expect(within(card).getByText("Evidence identity")).toBeVisible();
      const identity = within(card).getByText(standalone[i]!.asset_node_id);
      expect(identity.closest("details")).not.toHaveAttribute("open");
      expect(within(card).getByRole("link")).toHaveAttribute("href", `/security-graph?lens=attack-path&scan=scan-fixture&node=${encodeURIComponent(standalone[i]!.asset_node_id)}`);
    });
  });

});
