import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SegmentedLabel } from "@/components/graph-segmented-label";

function segments(text: string): string[] {
  const { container } = render(<SegmentedLabel text={text} />);
  return Array.from(container.querySelectorAll("p > span")).map((span) => span.textContent ?? "");
}

describe("SegmentedLabel", () => {
  it("keeps a package version together with its @", () => {
    expect(segments("form-data@4.0.0")).toEqual(["form-", "data", "@4.0.0"]);
  });

  it("does not split a leading scope @", () => {
    expect(segments("@types/node@20.1.0")).toEqual(["@types/", "node", "@20.1.0"]);
  });

  it("still breaks after separators", () => {
    expect(segments("prod_data/bucket")).toEqual(["prod_", "data/", "bucket"]);
  });
});
