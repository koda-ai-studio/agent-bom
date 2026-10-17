/** Historical tag lists remain bounded; source receipts qualify new associations. */
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FrameworkTagChips } from "@/components/framework-tag-chips";

// A historical wide tag list remains inspectable without reclassifying it.
const ATLAS_36 = [
  "AML.T0010", "AML.T0010.001", "AML.T0012", "AML.T0013", "AML.T0014",
  "AML.T0018", "AML.T0018.000", "AML.T0018.002", "AML.T0024", "AML.T0025",
  "AML.T0035", "AML.T0036", "AML.T0037", "AML.T0040", "AML.T0043",
  "AML.T0043.004", "AML.T0048", "AML.T0050", "AML.T0051", "AML.T0051.001",
  "AML.T0052", "AML.T0052.000", "AML.T0053", "AML.T0054", "AML.T0055",
  "AML.T0056", "AML.T0057", "AML.T0063", "AML.T0064", "AML.T0065",
  "AML.T0066", "AML.T0067", "AML.T0068", "AML.T0069", "AML.T0070",
  "AML.T0071",
];

const CATALOG = Object.fromEntries(ATLAS_36.map((id) => [id, `Technique ${id}`]));

function chips() {
  return screen.getAllByTestId("framework-tag-chip");
}

describe("FrameworkTagChips", () => {
  it("does not render 36 chips for one finding", () => {
    render(<FrameworkTagChips tags={ATLAS_36} catalog={CATALOG} tone="atlas" />);
    expect(chips().length).toBeLessThan(ATLAS_36.length);
  });

  it("keeps the hidden count honest rather than silently truncating", () => {
    render(<FrameworkTagChips tags={ATLAS_36} catalog={CATALOG} tone="atlas" />);
    const shown = chips().length;
    expect(screen.getByRole("button", { name: new RegExp(`${ATLAS_36.length - shown} more`) })).toBeVisible();
  });

  it("reveals every tag when the reader opens the rest, and collapses again", () => {
    render(<FrameworkTagChips tags={ATLAS_36} catalog={CATALOG} tone="atlas" />);
    const collapsed = chips().length;

    fireEvent.click(screen.getByRole("button", { name: /more/ }));
    expect(chips()).toHaveLength(ATLAS_36.length);

    fireEvent.click(screen.getByRole("button", { name: /show fewer/i }));
    expect(chips()).toHaveLength(collapsed);
  });

  it("renders a short tag list whole, with no disclosure control", () => {
    render(<FrameworkTagChips tags={["AML.T0010", "AML.T0012"]} catalog={CATALOG} tone="atlas" />);
    expect(chips()).toHaveLength(2);
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("renders nothing at all for a finding with no tags", () => {
    const { container } = render(<FrameworkTagChips tags={[]} catalog={CATALOG} tone="atlas" />);
    expect(container).toBeEmptyDOMElement();
  });

  it("names the technique, so a chip is readable without the catalog open", () => {
    render(<FrameworkTagChips tags={["AML.T0010"]} catalog={CATALOG} tone="atlas" />);
    expect(screen.getByTestId("framework-tag-chip")).toHaveAttribute("title", "Technique AML.T0010");
  });
});


it("qualifies ATLAS tags without asserting execution", () => {
  render(<FrameworkTagChips tags={["AML.T0037"]} catalog={CATALOG} tone="atlas" />);
  expect(screen.getByText("ATLAS associations · execution not established")).toBeVisible();
  expect(screen.queryByText("Mapping sources")).toBeNull();
});

it("exposes the frozen source chain and catalog receipts for mapped tags", () => {
  render(<FrameworkTagChips tags={["AML.T0037"]} catalog={CATALOG} tone="atlas" mappingEvidence={{
    "AML.T0037": { basis: "catalog_weakness_association", execution_proven: false,
      cwe_ids: ["CWE-285"], attack_reference: "T1005", atlas_version: "5.5.0",
      atlas_catalog_sha256: "a".repeat(64), attack_catalog_sha256: "b".repeat(64),
      technique_url: "https://atlas.mitre.org/techniques/AML.T0037" },
  }} />);
  fireEvent.click(screen.getByText("Mapping sources"));
  expect(screen.getByText("CWE-285 → T1005 → AML.T0037")).toBeInTheDocument();
  expect(screen.getByText("a".repeat(64))).toBeInTheDocument();
  expect(screen.getByText("b".repeat(64))).toBeInTheDocument();
});
