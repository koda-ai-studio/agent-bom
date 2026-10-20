import { readFileSync } from "node:fs";
import path from "node:path";

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RelationshipBadge, qualifiedLabel } from "@/components/relationship-edge";

describe("relationship badges", () => {
  it("keeps ownership and usage readable with different decorative icons", () => {
    const { container } = render(<>
      <RelationshipBadge relationship="owns">owns</RelationshipBadge>
      <RelationshipBadge relationship="uses">uses</RelationshipBadge>
    </>);
    expect(screen.getByText("owns")).toBeVisible();
    expect(screen.getByText("uses")).toBeVisible();
    const icons = container.querySelectorAll("svg");
    expect(icons).toHaveLength(2);
    expect(icons[0]!.innerHTML).not.toEqual(icons[1]!.innerHTML);
    for (const icon of icons) expect(icon).toHaveAttribute("aria-hidden", "true");
  });

  it("preserves unfamiliar recorded verbs with a neutral fallback icon", () => {
    render(<RelationshipBadge relationship="future_relation">future relation</RelationshipBadge>);
    expect(screen.getByText("future relation")).toBeVisible();
  });

  it("renders every canvas chip on one line and leaves the qualifier to assistive text and hover", () => {
    const { container } = render(<RelationshipBadge relationship="can_access">{qualifiedLabel("can_access", "Can Access · modeled", { evidenceMode: "inferred" })}</RelationshipBadge>);
    expect(container.querySelector(".graph-relationship-qualifier")).toBeNull();
    expect(screen.getByText("Can Access")).toBeVisible();
    expect(container.querySelector(".sr-only")).toHaveTextContent("· modeled");
    expect(container.textContent).toBe("Can Access · modeled");
    expect(qualifiedLabel("depends_on", "Depends On", { evidenceMode: "static" })).toBe("Depends On");
  });

  it("styles the canvas chip as one inline line, never a wrapped box", () => {
    const css = readFileSync(path.resolve(__dirname, "../app/globals.css"), "utf8");
    const rule = css.match(/\.graph-relationship-label \.relationship-badge \{([^}]*)\}/)?.[1] ?? "";
    expect(rule).toMatch(/white-space:\s*nowrap/);
    expect(rule).not.toMatch(/max-width:\s*8em/);
    expect(css).not.toMatch(/\.graph-relationship-qualifier\s*\{/);
  });
});
