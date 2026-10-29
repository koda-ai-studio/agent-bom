import { fireEvent, render, screen } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import { describe, expect, it } from "vitest";
import { lineageNodeTypes, type LineageNodeData } from "@/components/lineage-nodes";

function renderPackage(extra: Partial<LineageNodeData> = {}) {
  const Renderer = lineageNodeTypes.packageNode;
  return render(<ReactFlowProvider><Renderer data={{ label: "pillow@9.0.0", nodeType: "package", ...extra }} /></ReactFlowProvider>);
}

describe("package ecosystem glyph", () => {
  it.each([{ ecosystem: "pypi" }, { attributes: { ecosystem: "PyPI" } }])("uses the Python symbol with a separate PyPI ecosystem label: %j", (metadata) => {
    renderPackage(metadata);
    expect(screen.getByRole("img", { name: "Python package" })).toHaveAttribute("src", "/logos/python.svg");
    expect(screen.getByText("PyPI", { exact: true })).toBeVisible();
    expect(screen.getByText((_, element) => element?.tagName === "P" && element.textContent === "pillow@9.0.0")).toBeVisible();
  });

  it.each([{}, { ecosystem: "unknown" }, { ecosystem: "constructor" }, { ecosystem: "https://example.com/icon.svg" }])("does not infer PyPI from a familiar package name: %j", (metadata) => {
    const { container } = renderPackage(metadata);
    expect(screen.queryByRole("img", { name: "Python package" })).not.toBeInTheDocument();
    expect(container.querySelector('.graph-entity-glyph svg')).not.toBeNull();
  });

  it.each([
    ["npm", "npm", "npm package"], ["golang", "go", "Go package"],
    ["cargo", "rust", "Rust package"], ["nuget", "nuget", "NuGet package"],
    ["gem", "rubygems", "RubyGems package"], ["composer", "packagist", "Packagist package"],
  ])("shows a local ecosystem mark for recorded %s metadata", (ecosystem, asset, label) => {
    renderPackage({ ecosystem });
    expect(screen.getByRole("img", { name: label })).toHaveAttribute("src", `/logos/${asset}.svg`);
  });

  it("keeps the package glyph and ecosystem text if the image fails", () => {
    const { container } = renderPackage({ ecosystem: "pypi" });
    fireEvent.error(screen.getByRole("img", { name: "Python package" }));
    expect(container.querySelector('.graph-entity-glyph svg')).not.toBeNull();
    expect(screen.getByText("PyPI", { exact: true })).toBeVisible();
  });
});
