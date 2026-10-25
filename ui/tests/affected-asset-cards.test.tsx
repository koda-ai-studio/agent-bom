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
});
