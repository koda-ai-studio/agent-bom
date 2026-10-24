import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AdvisoryIdText, SegmentedLabel, atomicFontSize } from "@/components/graph-segmented-label";

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

describe("AdvisoryIdText", () => {
  it("renders an advisory id in a title as one no-wrap token after a break point", () => {
    const { container } = render(<h2><AdvisoryIdText text="Contractor Reviewer → CVE-2025-29927" /></h2>);
    const ids = container.querySelectorAll("[data-advisory-id]");
    expect(ids).toHaveLength(1);
    expect(ids[0]!.textContent).toBe("CVE-2025-29927");
    expect(ids[0]!.className).toContain("whitespace-nowrap");
    expect(ids[0]!.getAttribute("title")).toBe("CVE-2025-29927");
    expect(container.textContent).toBe("Contractor Reviewer → CVE-2025-29927");
  });

  it("keeps every GHSA and OSV id whole and leaves other text untouched", () => {
    const { container } = render(<p><AdvisoryIdText text="GHSA-j7hp-h8jx-5ppr and PYSEC-2023-12 via form-data" /></p>);
    expect(Array.from(container.querySelectorAll("[data-advisory-id]")).map(el => el.textContent))
      .toEqual(["GHSA-j7hp-h8jx-5ppr", "PYSEC-2023-12"]);
    expect(container.textContent).toBe("GHSA-j7hp-h8jx-5ppr and PYSEC-2023-12 via form-data");
  });

  it("renders text with no advisory id as plain text", () => {
    const { container } = render(<p><AdvisoryIdText text="analyst-agent → database" /></p>);
    expect(container.querySelector("[data-advisory-id]")).toBeNull();
    expect(container.querySelector("p")!.innerHTML).toBe("analyst-agent → database");
  });
});
