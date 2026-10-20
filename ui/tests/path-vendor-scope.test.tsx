import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";

import { PathVendorScopeChips } from "@/components/path-vendor-scope-chips";
import { crossVendorRequest, parseCrossVendor, vendorDisplayName } from "@/lib/path-vendor-scope";

const getGraphAttackPaths = vi.fn();
vi.mock("@/lib/api", () => ({ api: { getGraphAttackPaths: (...args: unknown[]) => getGraphAttackPaths(...args) } }));

const facets = {
  unit: "paths",
  snapshot_paths: 3417,
  cross_vendor_paths: 120,
  pairs: [
    { source_vendor: "github", target_vendor: "aws", paths: 63 },
    { source_vendor: "snowflake", target_vendor: "aws", paths: 57 },
  ],
  selected: null,
  covers_all_paths: true,
};

describe("path vendor scope", () => {
  beforeEach(() => getGraphAttackPaths.mockReset());

  it("parses the URL scope and turns it into a server request", () => {
    expect(parseCrossVendor(null)).toBe("");
    expect(parseCrossVendor("any")).toBe("any");
    expect(parseCrossVendor("snowflake>aws")).toBe("snowflake>aws");
    expect(parseCrossVendor("snowflake>*")).toBe("snowflake>*");
    expect(parseCrossVendor("bad value")).toBe("");
    expect(crossVendorRequest("")).toEqual({});
    expect(crossVendorRequest("any")).toEqual({ crossVendor: true });
    expect(crossVendorRequest("snowflake>*")).toEqual({ crossVendor: true, sourceVendor: "snowflake" });
    expect(crossVendorRequest("snowflake>aws")).toEqual({ crossVendor: true, sourceVendor: "snowflake", targetVendor: "aws" });
  });

  it("names vendors canonically", () => {
    expect(vendorDisplayName("aws")).toBe("AWS");
    expect(vendorDisplayName("snowflake")).toBe("Snowflake");
    expect(vendorDisplayName("huggingface")).toBe("Hugging Face");
    expect(vendorDisplayName("anthropic")).toBe("Anthropic");
    expect(vendorDisplayName("databricks")).toBe("Databricks");
    expect(vendorDisplayName("acme")).toBe("Acme");
  });

  it("offers a labelled cross-vendor preset and source-vendor chips with path counts", async () => {
    getGraphAttackPaths.mockResolvedValue({ vendor_facets: facets });
    const onChange = vi.fn();
    render(<PathVendorScopeChips scanId="scan-1" value="" onChange={onChange} />);
    expect(await screen.findByRole("button", { name: /Cross-vendor · 120 paths/ })).toBeInTheDocument();
    expect(getGraphAttackPaths).toHaveBeenCalledWith({ scanId: "scan-1", crossVendor: true, limit: 1 });
    // Every source vendor is one click away, whatever the number of pairs.
    fireEvent.click(screen.getByRole("button", { name: "From Snowflake · 57 paths" }));
    expect(onChange).toHaveBeenLastCalledWith("snowflake>*");
    expect(screen.getByRole("button", { name: "From GitHub · 63 paths" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^To / })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /Cross-vendor · 120 paths/ }));
    expect(onChange).toHaveBeenLastCalledWith("any");
  });

  it("narrows a chosen source vendor to one target vendor and clears back to all paths", async () => {
    getGraphAttackPaths.mockResolvedValue({ vendor_facets: facets });
    const onChange = vi.fn();
    const { rerender } = render(<PathVendorScopeChips scanId="scan-1" value="snowflake>*" onChange={onChange} />);
    expect(await screen.findByRole("button", { name: "From Snowflake · 57 paths" })).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(screen.getByRole("button", { name: "To AWS · 57 paths" }));
    expect(onChange).toHaveBeenLastCalledWith("snowflake>aws");
    rerender(<PathVendorScopeChips scanId="scan-1" value="snowflake>aws" onChange={onChange} />);
    expect(screen.getByRole("button", { name: "To AWS · 57 paths" })).toHaveAttribute("aria-pressed", "true");
    // A chosen source collapses the source list to keep the queue on screen.
    expect(screen.queryByRole("button", { name: "From GitHub · 63 paths" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Change source vendor" }));
    expect(screen.getByRole("button", { name: "From GitHub · 63 paths" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /All paths · 3,417/ }));
    expect(onChange).toHaveBeenLastCalledWith("");
  });

  it("says so when no path crosses vendors instead of rendering empty chips", async () => {
    getGraphAttackPaths.mockResolvedValue({ vendor_facets: { ...facets, cross_vendor_paths: 0, pairs: [] } });
    render(<PathVendorScopeChips scanId="scan-1" value="" onChange={() => {}} />);
    await waitFor(() => expect(screen.getByText(/No path in this snapshot starts and ends in different vendors/)).toBeInTheDocument());
  });
});
