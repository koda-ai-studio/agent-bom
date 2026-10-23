import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SegmentedLabel, atomicFontSize } from "@/components/graph-segmented-label";

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

  it("keeps a CVE id as one unbreakable segment", () => {
    expect(segments("CVE-2023-25577")).toEqual(["CVE-2023-25577"]);
  });

  it("keeps a GHSA id whole while still breaking the surrounding name", () => {
    expect(segments("pillow_GHSA-j7hp-h8jx-5ppr")).toEqual(["pillow_", "GHSA-j7hp-h8jx-5ppr"]);
  });

  it("keeps an advisory id whole when it is followed by more text", () => {
    expect(segments("PYSEC-2023-12-pillow")).toEqual(["PYSEC-2023-12", "-", "pillow"]);
  });

  it("marks an advisory id no-wrap, ellipsized, with the full id as its tooltip", () => {
    const { container } = render(<SegmentedLabel text="CVE-2023-25577" />);
    const span = container.querySelector("p > span");
    expect(span?.className).toContain("whitespace-nowrap");
    expect(span?.className).toContain("text-ellipsis");
    expect(span?.getAttribute("title")).toBe("CVE-2023-25577");
    expect(container.querySelectorAll("wbr")).toHaveLength(0);
  });

  it("leaves ordinary segments without a no-wrap class", () => {
    const { container } = render(<SegmentedLabel text="form-data" />);
    for (const span of Array.from(container.querySelectorAll("p > span"))) expect(span.className).not.toContain("whitespace-nowrap");
  });

  it("sizes an advisory id to the caption width instead of clipping it", () => {
    const { container } = render(<SegmentedLabel text="CVE-2023-4863" />);
    const id = container.querySelector("[data-advisory-id]") as HTMLElement;
    expect(id.textContent).toBe("CVE-2023-4863");
    expect(atomicFontSize("CVE-2023-4863")).toBe("min(1em, calc(100cqi / 8.58))");
    expect(id.style.fontSize).toContain("cqi");
    expect(container.querySelector("p")!.className).toContain("[container-type:inline-size]");
  });
});
