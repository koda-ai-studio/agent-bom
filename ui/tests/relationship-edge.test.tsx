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

  it("puts the evidence qualifier on its own line without changing the accessible text", () => {
    const { container } = render(<RelationshipBadge relationship="can_access">{qualifiedLabel("can_access", "Can Access · modeled", { evidenceMode: "inferred" })}</RelationshipBadge>);
    expect(container.querySelector(".graph-relationship-qualifier")).toHaveTextContent("modeled");
    expect(container.textContent).toBe("Can Access · modeled");
    expect(qualifiedLabel("depends_on", "Depends On", { evidenceMode: "static" })).toBe("Depends On");
  });

  it("keeps a compact canvas chip on one line and leaves the qualifier to assistive text", () => {
    const { container } = render(<RelationshipBadge relationship="uses">{qualifiedLabel("uses", "Uses · evidence unspecified", { evidenceMode: "unknown", compactEvidence: true })}</RelationshipBadge>);
    expect(container.querySelector(".graph-relationship-qualifier")).toBeNull();
    expect(screen.getByText("Uses")).toBeVisible();
    expect(container.querySelector(".sr-only")).toHaveTextContent("· evidence unspecified");
    expect(container.textContent).toBe("Uses · evidence unspecified");
  });
});
